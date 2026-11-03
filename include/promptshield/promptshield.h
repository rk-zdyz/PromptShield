/*
 * PromptShield — Prompt Injection Firewall
 * promptshield.h — Public C API
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef PROMPTSHIELD_H
#define PROMPTSHIELD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════
 * Version
 * ═══════════════════════════════════════════════════════════════ */
#include "version.h"

/* ═══════════════════════════════════════════════════════════════
 * Enumerations
 * ═══════════════════════════════════════════════════════════════ */

/** Verdict levels */
typedef enum {
    PS_VERDICT_SAFE       = 0,
    PS_VERDICT_SUSPICIOUS = 1,
    PS_VERDICT_MALICIOUS  = 2
} ps_verdict_t;

/** Detection layer identifiers */
typedef enum {
    PS_LAYER_UNICODE_NORM    = 0,
    PS_LAYER_AHO_CORASICK    = 1,
    PS_LAYER_STATISTICAL     = 2,
    PS_LAYER_CANARY          = 3,
    PS_LAYER_ML_CLASSIFIER   = 4,
    PS_LAYER_CONTEXT_TRACKER = 5,
    PS_LAYER_COUNT           = 6
} ps_layer_id_t;

/** Bitmask for layers */
#define PS_LAYER_BIT(id) (1u << (id))

/** Input data provenance source (G1: Greshake et al. §4) */
typedef enum {
    PS_SOURCE_USER        = 0,  /* Direct user-typed input */
    PS_SOURCE_RETRIEVAL   = 1,  /* Retrieved document / RAG / web search */
    PS_SOURCE_TOOL_OUTPUT = 2,  /* Tool / API execution response */
    PS_SOURCE_SYSTEM      = 3   /* System / developer prompt */
} ps_source_t;

/** Message role for structured input (G6: Ramakrishnan & Balaji) */
typedef enum {
    PS_ROLE_SYSTEM    = 0,
    PS_ROLE_USER      = 1,
    PS_ROLE_ASSISTANT = 2,
    PS_ROLE_TOOL      = 3
} ps_role_t;

/** Single message in structured conversation for boundary analysis */
typedef struct {
    ps_role_t   role;
    const char* content;
    size_t      content_len;
    int         trust_level;    /* 0 = untrusted (tool/retrieval), 1 = user, 2 = trusted system */
} ps_message_t;

/* ═══════════════════════════════════════════════════════════════
 * Result structures
 * ═══════════════════════════════════════════════════════════════ */

/** Maximum detail string length */
#define PS_DETAIL_MAX 256

/** Per-layer scan result */
typedef struct {
    ps_layer_id_t   layer_id;
    const char*     layer_name;
    ps_verdict_t    verdict;
    float           confidence;                 /* 0.0 — 1.0 */
    char            details[PS_DETAIL_MAX];     /* Human-readable explanation */
} ps_layer_result_t;

/** Maximum number of pattern matches to report */
#define PS_MAX_MATCHES 32

/** Pattern match info */
typedef struct {
    const char*     pattern;
    const char*     category;
    uint32_t        position;       /* Byte offset in normalized text */
} ps_match_t;

/** Full scan result */
typedef struct {
    ps_verdict_t        verdict;
    float               threat_score;           /* 0.0 — 1.0 aggregate */
    uint32_t            layers_triggered;       /* Bitmask of flagged layers */
    ps_layer_result_t   layers[PS_LAYER_COUNT];
    double              scan_time_us;           /* Total microseconds */
    ps_source_t         source;                 /* Input source (G1) */

    /* Pattern match details (from Aho-Corasick layer) */
    uint32_t            match_count;
    ps_match_t          matches[PS_MAX_MATCHES];
} ps_result_t;

/* ═══════════════════════════════════════════════════════════════
 * Context (opaque handle)
 * ═══════════════════════════════════════════════════════════════ */

typedef struct ps_context ps_context_t;

/* ═══════════════════════════════════════════════════════════════
 * Lifecycle
 * ═══════════════════════════════════════════════════════════════ */

/**
 * Create a new PromptShield context.
 * @param config_path  Path to config.json (NULL for defaults).
 * @return Opaque context handle, or NULL on error.
 */
ps_context_t* ps_create(const char* config_path);

/**
 * Destroy a context and free all resources.
 */
void ps_destroy(ps_context_t* ctx);

/* ═══════════════════════════════════════════════════════════════
 * Scanning
 * ═══════════════════════════════════════════════════════════════ */

/**
 * Scan input text for prompt injection.
 * @param ctx   Initialized context.
 * @param text  UTF-8 encoded input text.
 * @param len   Length in bytes (0 = strlen).
 * @return Scan result (stack-allocated, valid until next call).
 */
ps_result_t ps_scan_text(ps_context_t* ctx, const char* text, size_t len);

/**
 * Scan input text with explicit data provenance (G1: Greshake et al. §4).
 * Stricter thresholds and weighting applied for RETRIEVAL and TOOL_OUTPUT sources.
 * @param ctx     Initialized context.
 * @param text    UTF-8 encoded input text.
 * @param len     Length in bytes (0 = strlen).
 * @param source  Origin of data (USER, RETRIEVAL, TOOL_OUTPUT, SYSTEM).
 * @return Scan result.
 */
ps_result_t ps_scan_source(ps_context_t* ctx, const char* text, size_t len, ps_source_t source);

/**
 * Scan structured conversation messages with instruction-data boundary enforcement (G6: Ramakrishnan & Balaji).
 * Detects sandwich attacks, instruction leakage in untrusted tool/retrieval content,
 * and applies differential scoring by trust level.
 * @param ctx            Initialized context.
 * @param messages       Array of messages with roles and trust levels.
 * @param message_count  Number of messages.
 * @return Aggregate scan result for the conversation state.
 */
ps_result_t ps_scan_structured(ps_context_t* ctx, const ps_message_t* messages, size_t message_count);

/* ═══════════════════════════════════════════════════════════════
 * Multi-Step Agent Chain Tracking (G7: Ramakrishnan & Balaji)
 * ═══════════════════════════════════════════════════════════════ */

typedef struct ps_chain ps_chain_t;

/** Create an agent chain context for multi-agent workflows. */
ps_chain_t* ps_chain_create(size_t num_agents);

/** Destroy an agent chain context. */
void ps_chain_destroy(ps_chain_t* chain);

/**
 * Scan input at an agent step in the chain. Inherits contamination penalties
 * from upstream agents, triggering heightened alert mode if upstream poisoned.
 */
ps_result_t ps_chain_scan(ps_chain_t* chain, size_t agent_idx, ps_context_t* ctx,
                          const char* text, size_t len);

/** Get the current cumulative contamination score for an agent in the chain (0.0 — 1.0). */
float ps_chain_get_contamination(const ps_chain_t* chain, size_t agent_idx);

/** Generate a human-readable chain contamination timeline report. */
int ps_chain_report(const ps_chain_t* chain, char* buf, size_t buf_size);

/* ═══════════════════════════════════════════════════════════════
 * Canary Tokens
 * ═══════════════════════════════════════════════════════════════ */

/**
 * Generate a new canary token string.
 * @param ctx   Initialized context.
 * @param buf   Output buffer (must be >= 64 bytes).
 * @param size  Buffer size.
 * @return Length of canary string, or -1 on error.
 */
int ps_canary_generate(ps_context_t* ctx, char* buf, size_t size);

/**
 * Register a canary token for output monitoring.
 * @param ctx   Initialized context.
 * @param token Canary string to watch for.
 * @return 0 on success, -1 on error.
 */
int ps_canary_register(ps_context_t* ctx, const char* token);

/**
 * Scan LLM output for registered canary leakage.
 * @param ctx    Initialized context.
 * @param output UTF-8 encoded LLM output.
 * @param len    Length in bytes (0 = strlen).
 * @return Scan result focused on canary detection.
 */
ps_result_t ps_scan_output(ps_context_t* ctx, const char* output, size_t len);

/**
 * Clear all registered canary tokens.
 */
void ps_canary_clear(ps_context_t* ctx);

/**
 * Reset session history for cross-context contamination tracking.
 * Call this when starting a new conversation or user session.
 */
void ps_session_reset(ps_context_t* ctx);

/* ═══════════════════════════════════════════════════════════════
 * Configuration
 * ═══════════════════════════════════════════════════════════════ */

/**
 * Load/reload patterns from a JSON file.
 * @return 0 on success, -1 on error.
 */
int ps_load_patterns(ps_context_t* ctx, const char* path);

/**
 * Set a detection threshold for a specific layer.
 * @param layer_name  "aho_corasick", "statistical", "ml_classifier"
 * @param threshold   0.0 — 1.0
 * @return 0 on success, -1 if layer not found.
 */
int ps_set_threshold(ps_context_t* ctx, const char* layer_name, float threshold);

/* ═══════════════════════════════════════════════════════════════
 * Statistics
 * ═══════════════════════════════════════════════════════════════ */

/** Runtime statistics */
typedef struct {
    uint64_t total_scans;
    uint64_t verdicts[3];       /* safe / suspicious / malicious counts */
    double   avg_scan_time_us;
    double   total_scan_time_us;
} ps_stats_t;

/**
 * Get accumulated statistics.
 */
ps_stats_t ps_get_stats(const ps_context_t* ctx);

/**
 * Reset all statistics counters.
 */
void ps_reset_stats(ps_context_t* ctx);

/* ═══════════════════════════════════════════════════════════════
 * Utility
 * ═══════════════════════════════════════════════════════════════ */

/**
 * Get a human-readable string for a verdict.
 */
const char* ps_verdict_str(ps_verdict_t verdict);

/**
 * Get the library version string.
 */
const char* ps_version(void);

#ifdef __cplusplus
}
#endif

#endif /* PROMPTSHIELD_H */
