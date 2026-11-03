/*
 * PromptShield — Detection Pipeline Orchestrator
 * pipeline.c
 *
 * Runs the 5-layer detection pipeline:
 *   L1: Unicode normalization + homoglyph deobfuscation
 *   L2: Aho-Corasick multi-pattern matching
 *   L3: Statistical entropy + instruction density
 *   L4: Canary token leakage detection
 *   L5: ONNX DeBERTa ML classifier (optional)
 *
 * Aggregates layer verdicts into a final threat score.
 */

#include "pipeline.h"
#include "utils.h"
#include "promptshield/promptshield.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ═══════════════════════════════════════════════════════════════
 * Public API Implementation (promptshield.h)
 * ═══════════════════════════════════════════════════════════════ */

const char* ps_verdict_str(ps_verdict_t v) {
    switch (v) {
        case PS_VERDICT_SAFE:       return "SAFE";
        case PS_VERDICT_SUSPICIOUS: return "SUSPICIOUS";
        case PS_VERDICT_MALICIOUS:  return "MALICIOUS";
        default:                    return "UNKNOWN";
    }
}

const char* ps_version(void) {
    return PS_VERSION_STRING;
}

/* ═══════════════════════════════════════════════════════════════
 * Context Lifecycle
 * ═══════════════════════════════════════════════════════════════ */

ps_context_t* ps_create(const char* config_path) {
    ps_context_t* ctx = (ps_context_t*)calloc(1, sizeof(ps_context_t));
    if (!ctx) return NULL;

    /* Load configuration */
    ctx->config = ps_config_load(config_path);

    /* Initialize pipeline */
    if (pipeline_init(ctx) != 0) {
        ps_destroy(ctx);
        return NULL;
    }

    return ctx;
}

void ps_destroy(ps_context_t* ctx) {
    if (!ctx) return;

    un_destroy(ctx->unicode_ctx);
    ac_destroy(ctx->ac_ctx);
    canary_destroy(ctx->canary_ctx);
    ml_destroy(ctx->ml_ctx);
    ctx_tracker_destroy(ctx->ctx_tracker);

    free(ctx);
}

/* ═══════════════════════════════════════════════════════════════
 * Pipeline Initialization
 * ═══════════════════════════════════════════════════════════════ */

int pipeline_init(ps_context_t* ctx) {
    /* Layer 1: Unicode normalization */
    if (ctx->config.unicode_norm_enabled) {
        ctx->unicode_ctx = un_create(ctx->config.homoglyphs_path);
        /* Not fatal if NULL — works without homoglyph table */
    }

    /* Layer 2: Aho-Corasick pattern matcher */
    if (ctx->config.aho_corasick_enabled) {
        ctx->ac_ctx = ac_create();
        if (ctx->ac_ctx) {
            int loaded = ac_load_patterns_json(ctx->ac_ctx, ctx->config.patterns_path);
            if (loaded > 0) {
                ac_compile(ctx->ac_ctx);
            }
        }
    }

    /* Layer 4: Canary tokens */
    if (ctx->config.canary_enabled) {
        ctx->canary_ctx = canary_create();
    }

    /* Layer 5: ML classifier (optional) */
#ifdef PS_ENABLE_ONNX
    if (ctx->config.ml_enabled && ctx->config.model_path[0]) {
        ctx->ml_ctx = ml_create(ctx->config.model_path, ctx->config.vocab_path);
    }
#endif

    /* Layer 6: Context tracker (session history) */
    if (ctx->config.context_tracking_enabled) {
        ctx->ctx_tracker = ctx_tracker_create(ctx->config.context_window_size);
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════
 * Scanning — Core Pipeline
 * ═══════════════════════════════════════════════════════════════ */

static ps_result_t pipeline_scan_internal(ps_context_t* ctx, const char* text, size_t len, ps_source_t source) {
    ps_result_t result;
    memset(&result, 0, sizeof(result));
    result.source = source;

    if (!ctx || !text) return result;
    if (len == 0) len = strlen(text);
    if (len == 0) return result;

    double t_start = ps_time_us();
    const char* scan_text = text;
    size_t scan_len = len;

    /* Temporary storage for normalized and deobfuscated text */
    un_result_t un_result;
    memset(&un_result, 0, sizeof(un_result));
    char* deob_text = NULL;

    /* ─── Layer 1: Unicode Normalization & Deobfuscation (G2) ─── */
    ps_layer_result_t* lr1 = &result.layers[PS_LAYER_UNICODE_NORM];
    lr1->layer_id   = PS_LAYER_UNICODE_NORM;
    lr1->layer_name = "Unicode Normalization";

    if (ctx->config.unicode_norm_enabled && ctx->unicode_ctx) {
        un_result = un_normalize(ctx->unicode_ctx, text, len);

        if (un_result.normalized_text) {
            scan_text = un_result.normalized_text;
            scan_len  = un_result.normalized_len;
        }

        /* Secondary deobfuscation pass: decode base64, URL percent-encoding, leetspeak, HTML entities */
        deob_text = un_deobfuscate(scan_text, scan_len, &un_result);
        if (deob_text && strlen(deob_text) > 0) {
            scan_text = deob_text;
            scan_len  = strlen(deob_text);
        }

        lr1->confidence = un_result.suspicion_score;

        if (un_result.suspicion_score > 0.4f ||
            (un_result.flags & (UN_FLAG_BASE64_FOUND | UN_FLAG_URL_ENCODED_FOUND | UN_FLAG_LEETSPEAK_FOUND))) {
            lr1->verdict = (un_result.suspicion_score > 0.6f) ? PS_VERDICT_MALICIOUS : PS_VERDICT_SUSPICIOUS;
            result.layers_triggered |= PS_LAYER_BIT(PS_LAYER_UNICODE_NORM);
        } else if (un_result.suspicion_score > 0.1f) {
            lr1->verdict = PS_VERDICT_SUSPICIOUS;
            result.layers_triggered |= PS_LAYER_BIT(PS_LAYER_UNICODE_NORM);
        } else {
            lr1->verdict = PS_VERDICT_SAFE;
        }

        snprintf(lr1->details, PS_DETAIL_MAX,
                 "Homoglyphs: %u, Zero-width: %u%s%s%s%s%s",
                 un_result.homoglyph_count, un_result.zero_width_count,
                 (un_result.flags & UN_FLAG_MIXED_SCRIPT) ? ", Mixed scripts" : "",
                 (un_result.flags & UN_FLAG_FULLWIDTH_FOUND) ? ", Fullwidth" : "",
                 (un_result.flags & UN_FLAG_BASE64_FOUND) ? ", Base64 decoded" : "",
                 (un_result.flags & UN_FLAG_URL_ENCODED_FOUND) ? ", URL decoded" : "",
                 (un_result.flags & UN_FLAG_LEETSPEAK_FOUND) ? ", Leetspeak" : "");
    } else {
        lr1->verdict = PS_VERDICT_SAFE;
        snprintf(lr1->details, PS_DETAIL_MAX, "Disabled or no table loaded");
    }

    /* ─── Layer 2: Aho-Corasick Pattern Matching ─────────────── */
    ps_layer_result_t* lr2 = &result.layers[PS_LAYER_AHO_CORASICK];
    lr2->layer_id   = PS_LAYER_AHO_CORASICK;
    lr2->layer_name = "Pattern Matching";

    if (ctx->config.aho_corasick_enabled && ctx->ac_ctx) {
        ac_match_t ac_matches[PS_MAX_MATCHES];
        int match_count = ac_search(ctx->ac_ctx, scan_text, scan_len,
                                     ac_matches, PS_MAX_MATCHES);

        /* Copy matches to result */
        result.match_count = (uint32_t)(match_count < PS_MAX_MATCHES ? match_count : PS_MAX_MATCHES);
        for (uint32_t i = 0; i < result.match_count; i++) {
            result.matches[i].pattern  = ac_matches[i].pattern_text;
            result.matches[i].category = ac_pattern_category(ctx->ac_ctx, (int)ac_matches[i].pattern_id);
            result.matches[i].position = ac_matches[i].position;
        }

        /* Stricter threshold for indirect retrieval / tool sources (G1) */
        int min_mal = (source == PS_SOURCE_RETRIEVAL || source == PS_SOURCE_TOOL_OUTPUT) ? 1 : ctx->config.ac_min_malicious;
        int min_susp = (source == PS_SOURCE_RETRIEVAL || source == PS_SOURCE_TOOL_OUTPUT) ? 1 : ctx->config.ac_min_suspicious;

        if (match_count >= min_mal) {
            lr2->verdict    = PS_VERDICT_MALICIOUS;
            lr2->confidence = 0.9f + 0.01f * (float)(match_count - min_mal);
            if (lr2->confidence > 1.0f) lr2->confidence = 1.0f;
            result.layers_triggered |= PS_LAYER_BIT(PS_LAYER_AHO_CORASICK);
        } else if (match_count >= min_susp) {
            lr2->verdict    = PS_VERDICT_SUSPICIOUS;
            lr2->confidence = 0.5f + 0.2f * (float)match_count;
            if (lr2->confidence > 0.89f) lr2->confidence = 0.89f;
            result.layers_triggered |= PS_LAYER_BIT(PS_LAYER_AHO_CORASICK);
        } else {
            lr2->verdict    = PS_VERDICT_SAFE;
            lr2->confidence = 0.0f;
        }

        if (match_count > 0) {
            snprintf(lr2->details, PS_DETAIL_MAX,
                     "%d pattern(s) matched: \"%s\"%s%s",
                     match_count,
                     ac_matches[0].pattern_text,
                     match_count > 1 ? " (and more)" : "",
                     (source == PS_SOURCE_RETRIEVAL || source == PS_SOURCE_TOOL_OUTPUT) ? " [STRICT_PROVENANCE]" : "");
        } else {
            snprintf(lr2->details, PS_DETAIL_MAX, "No injection patterns found");
        }
    } else {
        lr2->verdict = PS_VERDICT_SAFE;
        snprintf(lr2->details, PS_DETAIL_MAX, "Disabled");
    }

    /* ─── Layer 6: Context Tracker (Cross-Context Contamination) ─ */
    ps_layer_result_t* lr6 = &result.layers[PS_LAYER_CONTEXT_TRACKER];
    lr6->layer_id   = PS_LAYER_CONTEXT_TRACKER;
    lr6->layer_name = "Context Tracker";

    if (ctx->config.context_tracking_enabled && ctx->ctx_tracker) {
        ctx_result_t ctr = ctx_tracker_analyze(ctx->ctx_tracker);
        lr6->confidence = ctr.contamination_score;
        ps_strlcpy(lr6->details, ctr.details, PS_DETAIL_MAX);

        if (ctr.escalation_detected || ctr.contamination_score > 0.6f) {
            lr6->verdict = PS_VERDICT_MALICIOUS;
            result.layers_triggered |= PS_LAYER_BIT(PS_LAYER_CONTEXT_TRACKER);
        } else if (ctr.velocity_alert || ctr.contamination_score > 0.25f || ctr.suspicious_run_length >= 2) {
            lr6->verdict = PS_VERDICT_SUSPICIOUS;
            result.layers_triggered |= PS_LAYER_BIT(PS_LAYER_CONTEXT_TRACKER);
        } else {
            lr6->verdict = PS_VERDICT_SAFE;
        }
    } else {
        lr6->verdict = PS_VERDICT_SAFE;
        snprintf(lr6->details, PS_DETAIL_MAX, "Disabled");
    }

    /* ─── Early exit check ────────────────────────────────────── */
    if (lr2->verdict == PS_VERDICT_MALICIOUS &&
        lr2->confidence >= ctx->config.early_exit_confidence) {
        /* Skip remaining heavy layers for speed */
        result.layers[PS_LAYER_STATISTICAL].layer_id   = PS_LAYER_STATISTICAL;
        result.layers[PS_LAYER_STATISTICAL].layer_name = "Statistical Analysis";
        snprintf(result.layers[PS_LAYER_STATISTICAL].details, PS_DETAIL_MAX, "Skipped (early exit)");

        result.layers[PS_LAYER_CANARY].layer_id   = PS_LAYER_CANARY;
        result.layers[PS_LAYER_CANARY].layer_name = "Canary Detection";
        snprintf(result.layers[PS_LAYER_CANARY].details, PS_DETAIL_MAX, "Skipped (early exit)");

        result.layers[PS_LAYER_ML_CLASSIFIER].layer_id   = PS_LAYER_ML_CLASSIFIER;
        result.layers[PS_LAYER_ML_CLASSIFIER].layer_name = "ML Classifier";
        snprintf(result.layers[PS_LAYER_ML_CLASSIFIER].details, PS_DETAIL_MAX, "Skipped (early exit)");

        result.verdict     = PS_VERDICT_MALICIOUS;
        result.threat_score = lr2->confidence;
        goto done;
    }

    /* ─── Layer 3: Statistical Analysis ──────────────────────── */
    ps_layer_result_t* lr3 = &result.layers[PS_LAYER_STATISTICAL];
    lr3->layer_id   = PS_LAYER_STATISTICAL;
    lr3->layer_name = "Statistical Analysis";

    if (ctx->config.statistical_enabled) {
        stat_result_t sr = stat_analyze(scan_text, scan_len, &ctx->config.stat);

        lr3->confidence = sr.suspicion_score;
        ps_strlcpy(lr3->details, sr.details, PS_DETAIL_MAX);

        if (sr.suspicion_score > 0.6f) {
            lr3->verdict = PS_VERDICT_MALICIOUS;
            result.layers_triggered |= PS_LAYER_BIT(PS_LAYER_STATISTICAL);
        } else if (sr.suspicion_score > 0.2f) {
            lr3->verdict = PS_VERDICT_SUSPICIOUS;
            result.layers_triggered |= PS_LAYER_BIT(PS_LAYER_STATISTICAL);
        } else {
            lr3->verdict = PS_VERDICT_SAFE;
        }
    } else {
        lr3->verdict = PS_VERDICT_SAFE;
        snprintf(lr3->details, PS_DETAIL_MAX, "Disabled");
    }

    /* ─── Layer 4: Canary Detection ──────────────────────────── */
    ps_layer_result_t* lr4 = &result.layers[PS_LAYER_CANARY];
    lr4->layer_id   = PS_LAYER_CANARY;
    lr4->layer_name = "Canary Detection";

    if (ctx->config.canary_enabled && ctx->canary_ctx &&
        canary_count(ctx->canary_ctx) > 0) {
        canary_result_t cr = canary_scan(ctx->canary_ctx, scan_text, scan_len);

        lr4->confidence = cr.confidence;
        ps_strlcpy(lr4->details, cr.details, PS_DETAIL_MAX);

        if (cr.leaked) {
            lr4->verdict = PS_VERDICT_MALICIOUS;
            result.layers_triggered |= PS_LAYER_BIT(PS_LAYER_CANARY);
        } else {
            lr4->verdict = PS_VERDICT_SAFE;
        }
    } else {
        lr4->verdict = PS_VERDICT_SAFE;
        snprintf(lr4->details, PS_DETAIL_MAX,
                 canary_count(ctx->canary_ctx) == 0 ? "No canaries registered" : "Disabled");
    }

    /* ─── Layer 5: ML Classifier ─────────────────────────────── */
    ps_layer_result_t* lr5 = &result.layers[PS_LAYER_ML_CLASSIFIER];
    lr5->layer_id   = PS_LAYER_ML_CLASSIFIER;
    lr5->layer_name = "ML Classifier";

    if (ctx->config.ml_enabled && ml_is_available(ctx->ml_ctx)) {
        ml_result_t mr = ml_classify(ctx->ml_ctx, scan_text, scan_len);

        lr5->confidence = mr.injection_prob;
        ps_strlcpy(lr5->details, mr.details, PS_DETAIL_MAX);

        if (mr.injection_prob >= ctx->config.ml_threshold_malicious) {
            lr5->verdict = PS_VERDICT_MALICIOUS;
            result.layers_triggered |= PS_LAYER_BIT(PS_LAYER_ML_CLASSIFIER);
        } else if (mr.injection_prob >= ctx->config.ml_threshold_suspicious) {
            lr5->verdict = PS_VERDICT_SUSPICIOUS;
            result.layers_triggered |= PS_LAYER_BIT(PS_LAYER_ML_CLASSIFIER);
        } else {
            lr5->verdict = PS_VERDICT_SAFE;
        }
    } else {
        lr5->verdict = PS_VERDICT_SAFE;
        snprintf(lr5->details, PS_DETAIL_MAX, "Not available");
    }

    /* ─── Aggregate verdict ──────────────────────────────────── */
    {
        float weighted_sum = 0.0f;
        float weight_total = 0.0f;

        /* Aho-Corasick */
        if (ctx->config.aho_corasick_enabled) {
            weighted_sum += lr2->confidence * ctx->config.weight_aho_corasick;
            weight_total += ctx->config.weight_aho_corasick;
        }

        /* Statistical */
        if (ctx->config.statistical_enabled) {
            weighted_sum += lr3->confidence * ctx->config.weight_statistical;
            weight_total += ctx->config.weight_statistical;
        }

        /* ML */
        if (ctx->config.ml_enabled && ml_is_available(ctx->ml_ctx)) {
            weighted_sum += lr5->confidence * ctx->config.weight_ml;
            weight_total += ctx->config.weight_ml;
        }

        /* Context tracker */
        if (ctx->config.context_tracking_enabled && ctx->ctx_tracker && ctx_tracker_count(ctx->ctx_tracker) > 0) {
            weighted_sum += lr6->confidence * ctx->config.weight_context_tracker;
            weight_total += ctx->config.weight_context_tracker;
        }

        /* Unicode (added as bonus, not part of primary weights) */
        if (lr1->confidence > 0.1f) {
            weighted_sum += lr1->confidence * 0.1f;
            weight_total += 0.1f;
        }

        /* Canary override: if canary leaked, force maximum threat */
        if (lr4->verdict == PS_VERDICT_MALICIOUS) {
            result.verdict      = PS_VERDICT_MALICIOUS;
            result.threat_score = 1.0f;
            goto done;
        }

        /* Compute final score */
        if (weight_total > 0.0f) {
            result.threat_score = weighted_sum / weight_total;
        }

        /* Indirect retrieval / tool provenance multiplier (G1) */
        if (source == PS_SOURCE_RETRIEVAL || source == PS_SOURCE_TOOL_OUTPUT) {
            result.threat_score *= 1.5f;
            if (result.threat_score > 1.0f) result.threat_score = 1.0f;
        }

        /* If high-severity direct injection was confirmed by Aho-Corasick or Unicode deobfuscation,
         * or if active multi-turn escalation was detected with current prompt signals,
         * ensure the threat_score reflects a malicious attack (> 0.60) */
        int other_layers_triggered = (result.layers_triggered & ~PS_LAYER_BIT(PS_LAYER_CONTEXT_TRACKER)) != 0;
        if ((lr2->verdict == PS_VERDICT_MALICIOUS || lr1->verdict == PS_VERDICT_MALICIOUS ||
             (lr6->verdict == PS_VERDICT_MALICIOUS && other_layers_triggered)) &&
            result.threat_score <= 0.60f) {
            float boost = (lr2->confidence > 0.0f) ? lr2->confidence :
                          (lr1->confidence > 0.0f) ? lr1->confidence : lr6->confidence;
            result.threat_score = 0.65f + 0.1f * (boost - 0.9f);
            if (result.threat_score <= 0.60f) result.threat_score = 0.65f;
            if (result.threat_score > 1.0f) result.threat_score = 1.0f;
        }

        /* Determine verdict strictly from threat score:
         * > 0.60 (above 60%)          -> MALICIOUS
         * > 0.20 (above 20%) to 0.60 -> SUSPICIOUS
         * <= 0.20 (20% or below)     -> SAFE
         */
        if (result.threat_score > 0.60f) {
            result.verdict = PS_VERDICT_MALICIOUS;
        } else if (result.threat_score > 0.20f) {
            result.verdict = PS_VERDICT_SUSPICIOUS;
        } else {
            result.verdict = PS_VERDICT_SAFE;
        }
    }

done:
    /* Record into session context tracker with semantic signals (G5) */
    if (ctx->config.context_tracking_enabled && ctx->ctx_tracker) {
        uint32_t cat_mask = 0;
        for (uint32_t m = 0; m < result.match_count; m++) {
            if (result.matches[m].category) {
                uint32_t h = 2166136261u;
                for (const char* p = result.matches[m].category; *p; p++)
                    h = (h ^ (unsigned char)*p) * 16777619u;
                cat_mask |= (1u << (h % 32));
            }
        }
        uint64_t text_hash = 14695981039346656037ULL;
        for (size_t k = 0; k < scan_len; k++) {
            text_hash = (text_hash ^ (unsigned char)scan_text[k]) * 1099511628211ULL;
        }
        ctx_tracker_record_ex(ctx->ctx_tracker, (int)result.verdict, result.threat_score,
                              result.layers_triggered, ps_time_us(),
                              cat_mask, text_hash, 0.0f);
    }

    result.scan_time_us = ps_time_us() - t_start;

    /* Update statistics */
    ctx->stats.total_scans++;
    ctx->stats.verdicts[result.verdict]++;
    ctx->stats.total_scan_time_us += result.scan_time_us;
    ctx->stats.avg_scan_time_us = ctx->stats.total_scan_time_us /
                                   (double)ctx->stats.total_scans;

    /* Clean up temporary buffers */
    if (deob_text) {
        free(deob_text);
    }
    if (un_result.normalized_text) {
        un_result_free(&un_result);
    }

    return result;
}

ps_result_t pipeline_scan_source(ps_context_t* ctx, const char* text, size_t len, ps_source_t source) {
    return pipeline_scan_internal(ctx, text, len, source);
}

ps_result_t pipeline_scan(ps_context_t* ctx, const char* text, size_t len) {
    return pipeline_scan_internal(ctx, text, len, PS_SOURCE_USER);
}

/* ═══════════════════════════════════════════════════════════════
 * Output scanning (canary-focused + exfiltration channels) (G4)
 * ═══════════════════════════════════════════════════════════════ */

ps_result_t pipeline_scan_output(ps_context_t* ctx, const char* output, size_t len) {
    ps_result_t result;
    memset(&result, 0, sizeof(result));

    if (!ctx || !output) return result;
    if (len == 0) len = strlen(output);

    double t_start = ps_time_us();

    /* Initialize all layer names */
    result.layers[PS_LAYER_UNICODE_NORM].layer_id   = PS_LAYER_UNICODE_NORM;
    result.layers[PS_LAYER_UNICODE_NORM].layer_name = "Unicode Normalization";
    snprintf(result.layers[PS_LAYER_UNICODE_NORM].details, PS_DETAIL_MAX, "N/A (output scan)");

    result.layers[PS_LAYER_AHO_CORASICK].layer_id   = PS_LAYER_AHO_CORASICK;
    result.layers[PS_LAYER_AHO_CORASICK].layer_name = "Pattern Matching";
    snprintf(result.layers[PS_LAYER_AHO_CORASICK].details, PS_DETAIL_MAX, "N/A (output scan)");

    result.layers[PS_LAYER_STATISTICAL].layer_id   = PS_LAYER_STATISTICAL;
    result.layers[PS_LAYER_STATISTICAL].layer_name = "Statistical Analysis";
    snprintf(result.layers[PS_LAYER_STATISTICAL].details, PS_DETAIL_MAX, "N/A (output scan)");

    result.layers[PS_LAYER_ML_CLASSIFIER].layer_id   = PS_LAYER_ML_CLASSIFIER;
    result.layers[PS_LAYER_ML_CLASSIFIER].layer_name = "ML Classifier";
    snprintf(result.layers[PS_LAYER_ML_CLASSIFIER].details, PS_DETAIL_MAX, "N/A (output scan)");

    result.layers[PS_LAYER_CONTEXT_TRACKER].layer_id   = PS_LAYER_CONTEXT_TRACKER;
    result.layers[PS_LAYER_CONTEXT_TRACKER].layer_name = "Context Tracker";
    snprintf(result.layers[PS_LAYER_CONTEXT_TRACKER].details, PS_DETAIL_MAX, "N/A (output scan)");

    ps_layer_result_t* lr4 = &result.layers[PS_LAYER_CANARY];
    lr4->layer_id   = PS_LAYER_CANARY;
    lr4->layer_name = "Canary Detection";

    /* 1. Canary leakage check */
    if (ctx->canary_ctx && canary_count(ctx->canary_ctx) > 0) {
        canary_result_t cr = canary_scan(ctx->canary_ctx, output, len);
        lr4->confidence = cr.confidence;
        ps_strlcpy(lr4->details, cr.details, PS_DETAIL_MAX);

        if (cr.leaked) {
            lr4->verdict          = PS_VERDICT_MALICIOUS;
            result.verdict        = PS_VERDICT_MALICIOUS;
            result.threat_score   = 1.0f;
            result.layers_triggered |= PS_LAYER_BIT(PS_LAYER_CANARY);
        }
    } else {
        snprintf(lr4->details, PS_DETAIL_MAX, "No canaries registered");
    }

    /* 2. Exfiltration channel detection (G4: markdown images / suspicious exfil URLs) */
    int exfil_found = 0;
    if (strstr(output, "![") != NULL && (strstr(output, "http://") || strstr(output, "https://"))) {
        exfil_found = 1;
    }
    if (strstr(output, "<img") != NULL && (strstr(output, "http://") || strstr(output, "https://"))) {
        exfil_found = 1;
    }
    if (strstr(output, "?data=") != NULL || strstr(output, "?leak=") != NULL ||
        strstr(output, "?payload=") != NULL || strstr(output, "?secret=") != NULL ||
        strstr(output, "?token=") != NULL) {
        exfil_found = 1;
    }

    if (exfil_found) {
        ps_layer_result_t* lr2 = &result.layers[PS_LAYER_AHO_CORASICK];
        lr2->verdict = PS_VERDICT_MALICIOUS;
        lr2->confidence = 0.95f;
        snprintf(lr2->details, PS_DETAIL_MAX, "Exfiltration channel detected (markdown image or exfil URL parameter)");
        result.verdict = PS_VERDICT_MALICIOUS;
        result.threat_score = 1.0f;
        result.layers_triggered |= PS_LAYER_BIT(PS_LAYER_AHO_CORASICK);
    }

    /* 3. Echo-back of sensitive patterns */
    if (ctx->ac_ctx && ctx->config.aho_corasick_enabled) {
        ac_match_t ac_matches[PS_MAX_MATCHES];
        int mcnt = ac_search(ctx->ac_ctx, output, len, ac_matches, PS_MAX_MATCHES);
        if (mcnt > 0) {
            ps_layer_result_t* lr2 = &result.layers[PS_LAYER_AHO_CORASICK];
            if (lr2->verdict < PS_VERDICT_SUSPICIOUS) {
                lr2->verdict = PS_VERDICT_SUSPICIOUS;
                lr2->confidence = 0.75f;
                snprintf(lr2->details, PS_DETAIL_MAX, "Prompt echo-back in output: matched \"%s\"", ac_matches[0].pattern_text);
                if (result.verdict < PS_VERDICT_SUSPICIOUS) {
                    result.verdict = PS_VERDICT_SUSPICIOUS;
                    if (result.threat_score < 0.6f) result.threat_score = 0.6f;
                }
                result.layers_triggered |= PS_LAYER_BIT(PS_LAYER_AHO_CORASICK);
            }
        }
    }

    result.scan_time_us = ps_time_us() - t_start;
    return result;
}

/* ═══════════════════════════════════════════════════════════════
 * Instruction-Data Boundary Enforcement (G6)
 * ═══════════════════════════════════════════════════════════════ */

ps_result_t pipeline_scan_structured(ps_context_t* ctx, const ps_message_t* messages, size_t message_count) {
    ps_result_t aggregate;
    memset(&aggregate, 0, sizeof(aggregate));
    if (!ctx || !messages || message_count == 0) return aggregate;

    double t_start = ps_time_us();
    float max_threat = 0.0f;
    int sandwich_attack = 0;
    int untrusted_attack = 0;

    for (size_t i = 0; i < message_count; i++) {
        ps_source_t src = PS_SOURCE_USER;
        if (messages[i].trust_level == 0 || messages[i].role == PS_ROLE_TOOL) {
            src = PS_SOURCE_TOOL_OUTPUT;
        } else if (messages[i].role == PS_ROLE_SYSTEM) {
            src = PS_SOURCE_SYSTEM;
        }

        ps_result_t r = pipeline_scan_internal(ctx, messages[i].content, messages[i].content_len, src);
        if (r.threat_score > max_threat) {
            max_threat = r.threat_score;
            aggregate = r;
        }

        /* Boundary violation: untrusted message contains directive instructions */
        if (messages[i].trust_level == 0 && (r.verdict >= PS_VERDICT_SUSPICIOUS || r.threat_score > 0.20f)) {
            untrusted_attack = 1;
            /* Sandwich attack: untrusted instruction flanked by user/system messages */
            if (i > 0 && i + 1 < message_count) {
                sandwich_attack = 1;
            }
        }
    }

    if (sandwich_attack) {
        aggregate.verdict = PS_VERDICT_MALICIOUS;
        aggregate.threat_score = 1.0f;
        snprintf(aggregate.layers[PS_LAYER_STATISTICAL].details, PS_DETAIL_MAX,
                 "Instruction-data boundary violation: Sandwich attack detected in untrusted turn");
        aggregate.layers_triggered |= PS_LAYER_BIT(PS_LAYER_STATISTICAL);
    } else if (untrusted_attack && aggregate.verdict < PS_VERDICT_MALICIOUS) {
        aggregate.verdict = PS_VERDICT_MALICIOUS;
        aggregate.threat_score = (aggregate.threat_score * 1.5f > 1.0f) ? 1.0f : aggregate.threat_score * 1.5f;
    }

    aggregate.scan_time_us = ps_time_us() - t_start;
    return aggregate;
}

/* ═══════════════════════════════════════════════════════════════
 * Multi-Step Agent Chain Tracking (G7)
 * ═══════════════════════════════════════════════════════════════ */

struct ps_chain {
    size_t  num_agents;
    float*  contamination_scores;
    int*    alert_mode;
};

ps_chain_t* ps_chain_create(size_t num_agents) {
    if (num_agents == 0) num_agents = 4;
    ps_chain_t* c = (ps_chain_t*)calloc(1, sizeof(ps_chain_t));
    if (!c) return NULL;
    c->num_agents = num_agents;
    c->contamination_scores = (float*)calloc(num_agents, sizeof(float));
    c->alert_mode = (int*)calloc(num_agents, sizeof(int));
    if (!c->contamination_scores || !c->alert_mode) {
        free(c->contamination_scores);
        free(c->alert_mode);
        free(c);
        return NULL;
    }
    return c;
}

void ps_chain_destroy(ps_chain_t* chain) {
    if (!chain) return;
    free(chain->contamination_scores);
    free(chain->alert_mode);
    free(chain);
}

ps_result_t ps_chain_scan(ps_chain_t* chain, size_t agent_idx, ps_context_t* ctx,
                          const char* text, size_t len) {
    ps_result_t r;
    memset(&r, 0, sizeof(r));
    if (!chain || !ctx || !text) return r;
    if (agent_idx >= chain->num_agents) agent_idx = chain->num_agents - 1;

    ps_source_t src = (agent_idx > 0 && chain->alert_mode[agent_idx - 1]) ? PS_SOURCE_TOOL_OUTPUT : PS_SOURCE_USER;
    r = pipeline_scan_source(ctx, text, len, src);

    /* Inherit contamination from previous agent */
    float base_penalty = (agent_idx > 0) ? chain->contamination_scores[agent_idx - 1] * 0.4f : 0.0f;
    r.threat_score += base_penalty;
    if (r.threat_score > 1.0f) r.threat_score = 1.0f;

    if (r.threat_score > 0.60f) r.verdict = PS_VERDICT_MALICIOUS;
    else if (r.threat_score > 0.20f && r.verdict < PS_VERDICT_SUSPICIOUS) r.verdict = PS_VERDICT_SUSPICIOUS;

    chain->contamination_scores[agent_idx] = r.threat_score;
    if (r.verdict == PS_VERDICT_MALICIOUS) {
        chain->alert_mode[agent_idx] = 1;
    }
    return r;
}

float ps_chain_get_contamination(const ps_chain_t* chain, size_t agent_idx) {
    if (!chain || agent_idx >= chain->num_agents) return 0.0f;
    return chain->contamination_scores[agent_idx];
}

int ps_chain_report(const ps_chain_t* chain, char* buf, size_t buf_size) {
    if (!chain || !buf || buf_size == 0) return -1;
    int written = 0;
    written += snprintf(buf + written, buf_size - written, "=== Agent Chain Contamination Timeline ===\n");
    for (size_t i = 0; i < chain->num_agents && (size_t)written < buf_size; i++) {
        written += snprintf(buf + written, buf_size - written,
                            "Agent #%zu: Contamination=%.2f | AlertMode=%s\n",
                            i, chain->contamination_scores[i],
                            chain->alert_mode[i] ? "ACTIVE" : "normal");
    }
    return written;
}

/* ═══════════════════════════════════════════════════════════════
 * Remaining Public API pass-throughs
 * ═══════════════════════════════════════════════════════════════ */

ps_result_t ps_scan_source(ps_context_t* ctx, const char* text, size_t len, ps_source_t source) {
    return pipeline_scan_source(ctx, text, len, source);
}

ps_result_t ps_scan_structured(ps_context_t* ctx, const ps_message_t* messages, size_t message_count) {
    return pipeline_scan_structured(ctx, messages, message_count);
}

ps_result_t ps_scan_text(ps_context_t* ctx, const char* text, size_t len) {
    return pipeline_scan(ctx, text, len);
}

ps_result_t ps_scan_output(ps_context_t* ctx, const char* output, size_t len) {
    return pipeline_scan_output(ctx, output, len);
}

void ps_session_reset(ps_context_t* ctx) {
    if (ctx && ctx->ctx_tracker) {
        ctx_tracker_reset(ctx->ctx_tracker);
    }
}

int ps_canary_generate(ps_context_t* ctx, char* buf, size_t size) {
    if (!ctx || !ctx->canary_ctx) return -1;
    return canary_generate(ctx->canary_ctx, buf, size);
}

int ps_canary_register(ps_context_t* ctx, const char* token) {
    if (!ctx || !ctx->canary_ctx) return -1;
    return canary_register(ctx->canary_ctx, token);
}

void ps_canary_clear(ps_context_t* ctx) {
    if (ctx && ctx->canary_ctx) canary_clear(ctx->canary_ctx);
}

int ps_load_patterns(ps_context_t* ctx, const char* path) {
    if (!ctx) return -1;

    /* Rebuild automaton */
    if (ctx->ac_ctx) ac_destroy(ctx->ac_ctx);
    ctx->ac_ctx = ac_create();
    if (!ctx->ac_ctx) return -1;

    int loaded = ac_load_patterns_json(ctx->ac_ctx, path);
    if (loaded <= 0) return -1;

    return ac_compile(ctx->ac_ctx);
}

int ps_set_threshold(ps_context_t* ctx, const char* layer_name, float threshold) {
    if (!ctx || !layer_name) return -1;

    if (ps_stricmp(layer_name, "aho_corasick") == 0 ||
        ps_stricmp(layer_name, "pattern") == 0) {
        /* Interpret as min-matches threshold */
        ctx->config.ac_min_suspicious = (int)(threshold * 3.0f);
        if (ctx->config.ac_min_suspicious < 1) ctx->config.ac_min_suspicious = 1;
        ctx->config.ac_min_malicious  = ctx->config.ac_min_suspicious + 1;
        return 0;
    }

    if (ps_stricmp(layer_name, "statistical") == 0) {
        ctx->config.stat.density_suspicious = threshold;
        ctx->config.stat.density_malicious  = threshold + 0.15f;
        return 0;
    }

    if (ps_stricmp(layer_name, "ml_classifier") == 0 ||
        ps_stricmp(layer_name, "ml") == 0) {
        ctx->config.ml_threshold_suspicious = threshold;
        ctx->config.ml_threshold_malicious  = threshold + 0.2f;
        if (ctx->config.ml_threshold_malicious > 1.0f)
            ctx->config.ml_threshold_malicious = 1.0f;
        return 0;
    }

    return -1;
}

ps_stats_t ps_get_stats(const ps_context_t* ctx) {
    if (ctx) return ctx->stats;
    ps_stats_t empty;
    memset(&empty, 0, sizeof(empty));
    return empty;
}

void ps_reset_stats(ps_context_t* ctx) {
    if (ctx) memset(&ctx->stats, 0, sizeof(ctx->stats));
}
