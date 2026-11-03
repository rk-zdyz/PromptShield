/*
 * PromptShield — Cross-Context Contamination Tracker
 * context_tracker.h
 *
 * Addresses Research Gap G5 from Ramakrishnan & Balaji (2025):
 * "Cross-context contamination — attacks that exploit how models
 *  maintain context across multiple retrieval rounds, causing
 *  persistent behavioral changes."
 *
 * Tracks scan history across a session to detect multi-turn
 * escalation patterns and cross-context contamination.
 */

#ifndef PS_CONTEXT_TRACKER_H
#define PS_CONTEXT_TRACKER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Default history window size */
#define CTX_DEFAULT_WINDOW_SIZE  16

/** Maximum supported window size */
#define CTX_MAX_WINDOW_SIZE      64

/** A single history entry from a past scan */
typedef struct {
    int         verdict;            /* 0=SAFE, 1=SUSPICIOUS, 2=MALICIOUS */
    float       threat_score;       /* 0.0 — 1.0 */
    uint32_t    layers_triggered;   /* Bitmask of flagged layers */
    double      timestamp_us;       /* Scan timestamp (microseconds) */
    uint32_t    categories_bitmask; /* Bitmask of triggered pattern categories (G5) */
    uint64_t    text_hash;          /* 64-bit fingerprint of normalized input (G5) */
    float       instruction_density;/* Imperative instruction density (G5) */
} ctx_history_entry_t;

/** Result from cross-context contamination analysis */
typedef struct {
    float       contamination_score;    /* 0.0 — 1.0 */
    int         escalation_detected;    /* Non-zero if escalation pattern found */
    int         velocity_alert;         /* Non-zero if rapid-fire scanning detected */
    int         suspicious_run_length;  /* Consecutive suspicious/malicious verdicts */
    int         total_malicious;        /* Total malicious verdicts in window */
    int         total_suspicious;       /* Total suspicious verdicts in window */
    int         category_persistence;   /* Non-zero if same category appears across 3+ turns (G5) */
    int         probe_similarity;       /* Non-zero if repeated near-identical probes detected (G5) */
    int         density_escalation;     /* Non-zero if instruction density increases monotonically (G5) */
    char        details[256];
} ctx_result_t;

/** Opaque context tracker handle */
typedef struct ctx_tracker ctx_tracker_t;

/**
 * Create a new context tracker.
 * @param window_size  Number of recent scans to track (0 = default 16).
 * @return Tracker handle, or NULL on error.
 */
ctx_tracker_t* ctx_tracker_create(int window_size);

/**
 * Destroy the context tracker and free resources.
 */
void ctx_tracker_destroy(ctx_tracker_t* tracker);

/**
 * Record a scan result into the history buffer.
 * @param tracker      Tracker handle.
 * @param verdict      Scan verdict (0/1/2).
 * @param threat_score Threat score (0.0-1.0).
 * @param layers       Bitmask of triggered layers.
 * @param timestamp_us Timestamp in microseconds.
 */
void ctx_tracker_record(ctx_tracker_t* tracker,
                        int verdict, float threat_score,
                        uint32_t layers, double timestamp_us);

/**
 * Record a scan result with semantic signals (G5).
 * @param tracker             Tracker handle.
 * @param verdict             Scan verdict (0/1/2).
 * @param threat_score        Threat score (0.0-1.0).
 * @param layers              Bitmask of triggered layers.
 * @param timestamp_us        Timestamp in microseconds.
 * @param categories_bitmask  Bitmask of pattern categories hit.
 * @param text_hash           64-bit hash of normalized text.
 * @param instruction_density Imperative density from statistical layer.
 */
void ctx_tracker_record_ex(ctx_tracker_t* tracker,
                           int verdict, float threat_score,
                           uint32_t layers, double timestamp_us,
                           uint32_t categories_bitmask, uint64_t text_hash,
                           float instruction_density);

/**
 * Analyze the scan history for cross-context contamination.
 * @param tracker  Tracker handle.
 * @return Contamination analysis result.
 */
ctx_result_t ctx_tracker_analyze(const ctx_tracker_t* tracker);

/**
 * Reset the session history (e.g., on new conversation).
 */
void ctx_tracker_reset(ctx_tracker_t* tracker);

/**
 * Get the number of recorded scans in the current session.
 */
int ctx_tracker_count(const ctx_tracker_t* tracker);

#ifdef __cplusplus
}
#endif

#endif /* PS_CONTEXT_TRACKER_H */
