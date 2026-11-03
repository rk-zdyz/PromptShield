/*
 * PromptShield — Canary Token Detection
 * canary.h
 */

#ifndef PS_CANARY_H
#define PS_CANARY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CANARY_MAX_TOKENS   32
#define CANARY_TOKEN_LEN    48   /* Max length of a single canary string */

/** Result from canary scanning */
typedef struct {
    int         leaked;             /* Non-zero if any canary found in output */
    int         leaked_count;       /* Number of distinct canaries found */
    int         leaked_indices[CANARY_MAX_TOKENS];  /* Which canaries leaked */
    float       confidence;         /* 1.0 if leaked, 0.0 otherwise */
    char        details[256];
} canary_result_t;

/** Opaque canary context */
typedef struct canary_context canary_context_t;

/** Create a canary context. */
canary_context_t* canary_create(void);

/** Destroy the canary context. */
void canary_destroy(canary_context_t* ctx);

/**
 * Generate a new random canary token.
 * @param ctx   Canary context.
 * @param buf   Output buffer.
 * @param size  Buffer size (>= 48 recommended).
 * @return Length of generated token, or -1 on error.
 */
int canary_generate(canary_context_t* ctx, char* buf, size_t size);

/**
 * Register a canary token for monitoring.
 * @return Index of registered canary (>= 0), or -1 on error.
 */
int canary_register(canary_context_t* ctx, const char* token);

/**
 * Scan text for any registered canary tokens.
 * @param ctx    Canary context with registered tokens.
 * @param text   Text to scan (typically LLM output).
 * @param len    Text length (0 = strlen).
 * @return Scan result.
 */
canary_result_t canary_scan(const canary_context_t* ctx, const char* text, size_t len);

/** Clear all registered canary tokens. */
void canary_clear(canary_context_t* ctx);

/** Get count of registered canary tokens. */
int canary_count(const canary_context_t* ctx);

#ifdef __cplusplus
}
#endif

#endif /* PS_CANARY_H */
