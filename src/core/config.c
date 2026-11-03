/*
 * PromptShield — Configuration Loader
 * config.c
 */

#include "config.h"
#include "utils.h"
#include "cJSON.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ═══════════════════════════════════════════════════════════════
 * Defaults
 * ═══════════════════════════════════════════════════════════════ */

ps_config_t ps_config_default(void) {
    ps_config_t c;
    memset(&c, 0, sizeof(c));

    c.unicode_norm_enabled      = 1;
    c.aho_corasick_enabled      = 1;
    c.statistical_enabled       = 1;
    c.canary_enabled            = 1;
    c.context_tracking_enabled  = 1;
    c.context_window_size       = 16;
    c.ml_enabled                = 0;

    ps_strlcpy(c.patterns_path,  "data/patterns.json", sizeof(c.patterns_path));
    ps_strlcpy(c.homoglyphs_path,"data/homoglyphs.json", sizeof(c.homoglyphs_path));

    c.ac_case_insensitive  = 1;
    c.ac_min_suspicious    = 1;
    c.ac_min_malicious     = 2;

    c.stat = stat_default_config();

    c.ml_threshold_suspicious = 0.7f;
    c.ml_threshold_malicious  = 0.9f;
    c.ml_max_seq_len          = 512;

    c.early_exit_confidence    = 0.95f;
    c.weight_aho_corasick      = 0.30f;
    c.weight_statistical       = 0.20f;
    c.weight_ml                = 0.30f;
    c.weight_canary            = 0.10f;
    c.weight_context_tracker   = 0.10f;

    ps_strlcpy(c.server_host, "127.0.0.1", sizeof(c.server_host));
    c.server_port       = 8720;
    c.server_threads    = 4;
    c.server_timeout_ms = 5000;
    ps_strlcpy(c.server_cors, "*", sizeof(c.server_cors));
    c.server_dashboard  = 1;

    return c;
}

/* ═══════════════════════════════════════════════════════════════
 * JSON parsing helpers
 * ═══════════════════════════════════════════════════════════════ */

static int json_bool(const cJSON* obj, const char* key, int def) {
    cJSON* v = cJSON_GetObjectItem(obj, key);
    if (cJSON_IsBool(v)) return cJSON_IsTrue(v) ? 1 : 0;
    return def;
}

static float json_float(const cJSON* obj, const char* key, float def) {
    cJSON* v = cJSON_GetObjectItem(obj, key);
    if (cJSON_IsNumber(v)) return (float)v->valuedouble;
    return def;
}

static int json_int(const cJSON* obj, const char* key, int def) {
    cJSON* v = cJSON_GetObjectItem(obj, key);
    if (cJSON_IsNumber(v)) return v->valueint;
    return def;
}

static void json_str(const cJSON* obj, const char* key, char* dst, size_t size,
                     const char* def) {
    cJSON* v = cJSON_GetObjectItem(obj, key);
    if (cJSON_IsString(v) && v->valuestring)
        ps_strlcpy(dst, v->valuestring, size);
    else if (def)
        ps_strlcpy(dst, def, size);
}

/* ═══════════════════════════════════════════════════════════════
 * Load from JSON
 * ═══════════════════════════════════════════════════════════════ */

ps_config_t ps_config_load(const char* path) {
    ps_config_t cfg = ps_config_default();

    if (!path) return cfg;

    size_t flen = 0;
    char* json_str_buf = ps_read_file(path, &flen);
    if (!json_str_buf) return cfg;

    cJSON* root = cJSON_Parse(json_str_buf);
    free(json_str_buf);
    if (!root) return cfg;

    cJSON* ps = cJSON_GetObjectItem(root, "promptshield");
    if (!ps) { cJSON_Delete(root); return cfg; }

    /* Layers */
    cJSON* layers = cJSON_GetObjectItem(ps, "layers");
    if (layers) {
        cJSON* un = cJSON_GetObjectItem(layers, "unicode_norm");
        if (un) cfg.unicode_norm_enabled = json_bool(un, "enabled", cfg.unicode_norm_enabled);

        cJSON* ac = cJSON_GetObjectItem(layers, "aho_corasick");
        if (ac) {
            cfg.aho_corasick_enabled = json_bool(ac, "enabled", cfg.aho_corasick_enabled);
            cfg.ac_case_insensitive  = json_bool(ac, "case_insensitive", cfg.ac_case_insensitive);
            json_str(ac, "patterns_file", cfg.patterns_path, sizeof(cfg.patterns_path), NULL);
            cfg.ac_min_suspicious    = json_int(ac, "min_matches_suspicious", cfg.ac_min_suspicious);
            cfg.ac_min_malicious     = json_int(ac, "min_matches_malicious", cfg.ac_min_malicious);
        }

        cJSON* st = cJSON_GetObjectItem(layers, "statistical");
        if (st) {
            cfg.statistical_enabled        = json_bool(st, "enabled", cfg.statistical_enabled);
            cfg.stat.entropy_high          = json_float(st, "entropy_high_threshold", cfg.stat.entropy_high);
            cfg.stat.entropy_low           = json_float(st, "entropy_low_threshold", cfg.stat.entropy_low);
            cfg.stat.density_suspicious    = json_float(st, "instruction_density_suspicious", cfg.stat.density_suspicious);
            cfg.stat.density_malicious     = json_float(st, "instruction_density_malicious", cfg.stat.density_malicious);
            cfg.stat.min_text_length       = json_int(st, "min_text_length", cfg.stat.min_text_length);
        }

        cJSON* ca = cJSON_GetObjectItem(layers, "canary");
        if (ca) cfg.canary_enabled = json_bool(ca, "enabled", cfg.canary_enabled);

        cJSON* ct = cJSON_GetObjectItem(layers, "context_tracker");
        if (ct) {
            cfg.context_tracking_enabled = json_bool(ct, "enabled", cfg.context_tracking_enabled);
            cfg.context_window_size      = json_int(ct, "window_size", cfg.context_window_size);
        }

        cJSON* ml = cJSON_GetObjectItem(layers, "ml_classifier");
        if (ml) {
            cfg.ml_enabled              = json_bool(ml, "enabled", cfg.ml_enabled);
            json_str(ml, "model_path", cfg.model_path, sizeof(cfg.model_path), NULL);
            json_str(ml, "vocab_path", cfg.vocab_path, sizeof(cfg.vocab_path), NULL);
            cfg.ml_threshold_suspicious = json_float(ml, "threshold_suspicious", cfg.ml_threshold_suspicious);
            cfg.ml_threshold_malicious  = json_float(ml, "threshold_malicious", cfg.ml_threshold_malicious);
            cfg.ml_max_seq_len          = json_int(ml, "max_sequence_length", cfg.ml_max_seq_len);
        }
    }

    /* Pipeline */
    cJSON* pipe = cJSON_GetObjectItem(ps, "pipeline");
    if (pipe) {
        cfg.early_exit_confidence = json_float(pipe, "early_exit_confidence", cfg.early_exit_confidence);
        cJSON* w = cJSON_GetObjectItem(pipe, "weights");
        if (w) {
            cfg.weight_aho_corasick     = json_float(w, "aho_corasick", cfg.weight_aho_corasick);
            cfg.weight_statistical      = json_float(w, "statistical", cfg.weight_statistical);
            cfg.weight_ml               = json_float(w, "ml_classifier", cfg.weight_ml);
            cfg.weight_canary           = json_float(w, "canary", cfg.weight_canary);
            cfg.weight_context_tracker  = json_float(w, "context_tracker", cfg.weight_context_tracker);
        }
    }

    /* Server */
    cJSON* srv = cJSON_GetObjectItem(ps, "server");
    if (srv) {
        json_str(srv, "host", cfg.server_host, sizeof(cfg.server_host), NULL);
        cfg.server_port       = json_int(srv, "port", cfg.server_port);
        cfg.server_threads    = json_int(srv, "num_threads", cfg.server_threads);
        cfg.server_timeout_ms = json_int(srv, "request_timeout_ms", cfg.server_timeout_ms);
        json_str(srv, "cors_origin", cfg.server_cors, sizeof(cfg.server_cors), NULL);
        cfg.server_dashboard  = json_bool(srv, "enable_dashboard", cfg.server_dashboard);
    }

    cJSON_Delete(root);
    return cfg;
}
