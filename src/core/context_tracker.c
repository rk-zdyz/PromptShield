/*
 * PromptShield — Cross-Context Contamination Tracker
 * context_tracker.c
 *
 * Addresses Research Gap G5 from Ramakrishnan & Balaji (2025):
 * Detects multi-turn escalation patterns and cross-context
 * contamination by tracking scan history across a session.
 *
 * Detection heuristics:
 *   1. Escalation: Consecutive suspicious/malicious verdicts
 *   2. Velocity: Rapid-fire requests (potential automated attack)
 *   3. Persistence: High ratio of flagged verdicts across window
 */

#include "context_tracker.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ═══════════════════════════════════════════════════════════════
 * Internal structure
 * ═══════════════════════════════════════════════════════════════ */

struct ctx_tracker {
    ctx_history_entry_t*    history;     /* Ring buffer */
    int                     window_size; /* Buffer capacity */
    int                     count;       /* Total entries recorded */
    int                     head;        /* Next write position */
};

/* ═══════════════════════════════════════════════════════════════
 * Lifecycle
 * ═══════════════════════════════════════════════════════════════ */

ctx_tracker_t* ctx_tracker_create(int window_size) {
    if (window_size <= 0)
        window_size = CTX_DEFAULT_WINDOW_SIZE;
    if (window_size > CTX_MAX_WINDOW_SIZE)
        window_size = CTX_MAX_WINDOW_SIZE;

    ctx_tracker_t* t = (ctx_tracker_t*)calloc(1, sizeof(ctx_tracker_t));
    if (!t) return NULL;

    t->history = (ctx_history_entry_t*)calloc(
        (size_t)window_size, sizeof(ctx_history_entry_t));
    if (!t->history) {
        free(t);
        return NULL;
    }

    t->window_size = window_size;
    t->count = 0;
    t->head = 0;

    return t;
}

void ctx_tracker_destroy(ctx_tracker_t* tracker) {
    if (!tracker) return;
    free(tracker->history);
    free(tracker);
}

/* ═══════════════════════════════════════════════════════════════
 * Recording
 * ═══════════════════════════════════════════════════════════════ */

/* ═══════════════════════════════════════════════════════════════
 * Recording
 * ═══════════════════════════════════════════════════════════════ */

void ctx_tracker_record_ex(ctx_tracker_t* tracker,
                           int verdict, float threat_score,
                           uint32_t layers, double timestamp_us,
                           uint32_t categories_bitmask, uint64_t text_hash,
                           float instruction_density) {
    if (!tracker) return;

    ctx_history_entry_t* entry = &tracker->history[tracker->head];
    entry->verdict             = verdict;
    entry->threat_score        = threat_score;
    entry->layers_triggered    = layers;
    entry->timestamp_us        = timestamp_us;
    entry->categories_bitmask  = categories_bitmask;
    entry->text_hash           = text_hash;
    entry->instruction_density = instruction_density;

    tracker->head = (tracker->head + 1) % tracker->window_size;
    tracker->count++;
}

void ctx_tracker_record(ctx_tracker_t* tracker,
                        int verdict, float threat_score,
                        uint32_t layers, double timestamp_us) {
    ctx_tracker_record_ex(tracker, verdict, threat_score, layers, timestamp_us, 0, 0, 0.0f);
}

/* ═══════════════════════════════════════════════════════════════
 * Analysis
 * ═══════════════════════════════════════════════════════════════ */

ctx_result_t ctx_tracker_analyze(const ctx_tracker_t* tracker) {
    ctx_result_t r;
    memset(&r, 0, sizeof(r));

    if (!tracker || tracker->count == 0) {
        snprintf(r.details, sizeof(r.details), "No session history");
        return r;
    }

    int entries = tracker->count < tracker->window_size
                  ? tracker->count : tracker->window_size;

    /* ── Compute statistics over the history window ────────── */
    int malicious_count   = 0;
    int suspicious_count  = 0;
    float score_sum       = 0.0f;
    int current_run       = 0;   /* Current consecutive non-safe run */
    int max_run           = 0;   /* Longest consecutive non-safe run */
    double min_ts         = 0.0;
    double max_ts         = 0.0;
    int first             = 1;

    /* Semantic tracking signals (G5) */
    uint32_t cat_counts[32] = {0};
    int density_increases = 0;

    /* Iterate from oldest to newest entry */
    int start_idx;
    if (tracker->count >= tracker->window_size) {
        start_idx = tracker->head;  /* Oldest entry (ring wrapped) */
    } else {
        start_idx = 0;
    }

    for (int i = 0; i < entries; i++) {
        int idx = (start_idx + i) % tracker->window_size;
        const ctx_history_entry_t* e = &tracker->history[idx];

        score_sum += e->threat_score;

        if (e->verdict >= 2) {   /* MALICIOUS */
            malicious_count++;
            current_run++;
        } else if (e->verdict >= 1) {  /* SUSPICIOUS */
            suspicious_count++;
            current_run++;
        } else {
            if (current_run > max_run) max_run = current_run;
            current_run = 0;
        }

        /* Category persistence check */
        if (e->categories_bitmask > 0) {
            for (int b = 0; b < 32; b++) {
                if (e->categories_bitmask & (1u << b)) {
                    cat_counts[b]++;
                    if (cat_counts[b] >= 3) {
                        r.category_persistence = 1;
                    }
                }
            }
        }

        /* Probe similarity check (duplicate fingerprints) */
        if (e->text_hash != 0) {
            for (int j = 0; j < i; j++) {
                int prev_idx = (start_idx + j) % tracker->window_size;
                if (tracker->history[prev_idx].text_hash == e->text_hash) {
                    r.probe_similarity = 1;
                    break;
                }
            }
        }

        /* Track time range for velocity detection */
        if (first || e->timestamp_us < min_ts) min_ts = e->timestamp_us;
        if (first || e->timestamp_us > max_ts) max_ts = e->timestamp_us;
        first = 0;
    }
    if (current_run > max_run) max_run = current_run;

    r.total_malicious       = malicious_count;
    r.total_suspicious      = suspicious_count;
    r.suspicious_run_length = max_run;

    /* ── Escalation detection ─────────────────────────────── */
    int escalation_steps = 0;
    if (entries >= 3) {
        for (int i = 1; i < entries; i++) {
            int idx_prev = (start_idx + i - 1) % tracker->window_size;
            int idx_curr = (start_idx + i) % tracker->window_size;

            if (tracker->history[idx_curr].threat_score >=
                tracker->history[idx_prev].threat_score + 0.01f) {
                escalation_steps++;
            }
            if (tracker->history[idx_curr].instruction_density >=
                tracker->history[idx_prev].instruction_density + 0.02f) {
                density_increases++;
            }
        }
    }

    /* If >50% of transitions are escalating, flag it */
    if (entries >= 3 && escalation_steps >= (entries - 1) / 2) {
        r.escalation_detected = 1;
    }
    if (entries >= 3 && density_increases >= 2) {
        r.density_escalation = 1;
    }

    /* ── Velocity detection ───────────────────────────────── */
    if (entries >= 5 && max_ts > min_ts) {
        double duration_seconds = (max_ts - min_ts) / 1e6;
        double rate = (double)entries / duration_seconds;  /* scans/sec */
        if (rate > 10.0) {
            r.velocity_alert = 1;
        }
    }

    /* ── Contamination score ──────────────────────────────── */
    float persistence_ratio = (float)(malicious_count + suspicious_count)
                              / (float)entries;
    float avg_score = score_sum / (float)entries;
    float run_factor = (float)max_run / (float)entries;

    float score = persistence_ratio * 0.35f
                + avg_score * 0.25f
                + run_factor * 0.15f
                + (r.escalation_detected ? 0.05f : 0.0f)
                + (r.velocity_alert ? 0.05f : 0.0f)
                + (r.category_persistence ? 0.10f : 0.0f)
                + (r.probe_similarity ? 0.05f : 0.0f)
                + (r.density_escalation ? 0.05f : 0.0f);

    if (score > 1.0f) score = 1.0f;
    r.contamination_score = score;

    /* ── Build details string ─────────────────────────────── */
    snprintf(r.details, sizeof(r.details),
             "Session: %d scans | Mal: %d, Susp: %d | Run: %d | "
             "Contamination: %.2f%s%s%s",
             entries, malicious_count, suspicious_count, max_run,
             r.contamination_score,
             r.escalation_detected ? " | ESCALATION" : "",
             r.category_persistence ? " | CATEGORY_PERSISTENCE" : "",
             r.probe_similarity ? " | REPEATED_PROBE" : "");

    return r;
}

/* ═══════════════════════════════════════════════════════════════
 * Utility
 * ═══════════════════════════════════════════════════════════════ */

void ctx_tracker_reset(ctx_tracker_t* tracker) {
    if (!tracker) return;
    memset(tracker->history, 0,
           (size_t)tracker->window_size * sizeof(ctx_history_entry_t));
    tracker->count = 0;
    tracker->head  = 0;
}

int ctx_tracker_count(const ctx_tracker_t* tracker) {
    return tracker ? tracker->count : 0;
}
