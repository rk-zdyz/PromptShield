/*
 * PromptShield — Statistical Analysis Layer
 * statistical.h
 */

#ifndef PS_STATISTICAL_H
#define PS_STATISTICAL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Statistical analysis result */
typedef struct {
    float   char_entropy;           /* Shannon entropy per character (bits) */
    float   instruction_density;    /* Ratio of imperative tokens to total */
    int     imperative_count;       /* Number of imperative/directive tokens found */
    int     total_tokens;           /* Total word tokens */
    float   self_replication_score; /* 0.0 — 1.0 Worm/propagation detection (G9) */
    float   suspicion_score;        /* 0.0 — 1.0 aggregate */
    char    details[256];           /* Human-readable summary */
} stat_result_t;

/** Configuration for statistical analysis */
typedef struct {
    float   entropy_high;           /* High entropy threshold (default 4.5) */
    float   entropy_low;            /* Low entropy threshold (default 2.0) */
    float   density_suspicious;     /* Instruction density suspicious (default 0.15) */
    float   density_malicious;      /* Instruction density malicious (default 0.30) */
    int     min_text_length;        /* Minimum text length for analysis (default 10) */
} stat_config_t;

/** Get default statistical configuration. */
stat_config_t stat_default_config(void);

/**
 * Perform statistical analysis on text.
 * @param text   Input text (should be pre-normalized).
 * @param len    Text length (0 = strlen).
 * @param config Configuration thresholds.
 * @return Analysis result.
 */
stat_result_t stat_analyze(const char* text, size_t len, const stat_config_t* config);

#ifdef __cplusplus
}
#endif

#endif /* PS_STATISTICAL_H */
