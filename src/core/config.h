/*
 * PromptShield — Configuration Loader
 * config.h
 */

#ifndef PS_CONFIG_H
#define PS_CONFIG_H

#include "statistical.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Full configuration structure */
typedef struct {
    /* Layer enable flags */
    int         unicode_norm_enabled;
    int         aho_corasick_enabled;
    int         statistical_enabled;
    int         canary_enabled;
    int         context_tracking_enabled;
    int         context_window_size;
    int         ml_enabled;

    /* Paths */
    char        patterns_path[512];
    char        homoglyphs_path[512];
    char        model_path[512];
    char        vocab_path[512];

    /* Aho-Corasick */
    int         ac_case_insensitive;
    int         ac_min_suspicious;
    int         ac_min_malicious;

    /* Statistical thresholds */
    stat_config_t stat;

    /* ML thresholds */
    float       ml_threshold_suspicious;
    float       ml_threshold_malicious;
    int         ml_max_seq_len;

    /* Pipeline */
    float       early_exit_confidence;
    float       weight_aho_corasick;
    float       weight_statistical;
    float       weight_ml;
    float       weight_canary;
    float       weight_context_tracker;

    /* Server */
    char        server_host[64];
    int         server_port;
    int         server_threads;
    int         server_timeout_ms;
    char        server_cors[256];
    int         server_dashboard;
} ps_config_t;

/** Load configuration from JSON file. Returns defaults if path is NULL or file missing. */
ps_config_t ps_config_load(const char* path);

/** Get default configuration. */
ps_config_t ps_config_default(void);

#ifdef __cplusplus
}
#endif

#endif /* PS_CONFIG_H */
