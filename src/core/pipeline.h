/*
 * PromptShield — Detection Pipeline
 * pipeline.h
 */

#ifndef PS_PIPELINE_H
#define PS_PIPELINE_H

#include "promptshield/promptshield.h"
#include "config.h"
#include "aho_corasick.h"
#include "unicode_norm.h"
#include "statistical.h"
#include "canary.h"
#include "ml_classifier.h"
#include "context_tracker.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Internal context (the full opaque ps_context_t) */
struct ps_context {
    ps_config_t         config;

    /* Detection engines */
    un_context_t*       unicode_ctx;
    ac_automaton_t*     ac_ctx;
    canary_context_t*   canary_ctx;
    ml_context_t*       ml_ctx;
    ctx_tracker_t*      ctx_tracker;

    /* Statistics */
    ps_stats_t          stats;
};

/** Initialize the pipeline with the given config. */
int pipeline_init(ps_context_t* ctx);

/** Run the full detection pipeline on input text with source provenance. */
ps_result_t pipeline_scan_source(ps_context_t* ctx, const char* text, size_t len, ps_source_t source);

/** Run the full detection pipeline on input text (default: PS_SOURCE_USER). */
ps_result_t pipeline_scan(ps_context_t* ctx, const char* text, size_t len);

/** Run structured multi-message boundary scan. */
ps_result_t pipeline_scan_structured(ps_context_t* ctx, const ps_message_t* messages, size_t message_count);

/** Run output scan (canary detection + exfiltration URL/markdown analysis). */
ps_result_t pipeline_scan_output(ps_context_t* ctx, const char* output, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PS_PIPELINE_H */
