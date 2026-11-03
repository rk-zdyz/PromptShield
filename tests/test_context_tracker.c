/*
 * PromptShield — Context Tracker Unit Tests (G5 Defense)
 */

#include "context_tracker.h"
#include <stdio.h>
#include <string.h>

static int tests_passed = 0;
static int tests_total = 0;

#define ASSERT(cond) do { \
    tests_total++; \
    if (!(cond)) { printf("[FAIL] %s:%d: %s\n", __FILE__, __LINE__, #cond); return; } \
    tests_passed++; \
} while(0)

#define TEST(name) static void name(void)
#define RUN(name) do { printf("  %-50s", #name); name(); printf("[PASS]\n"); } while(0)

TEST(test_tracker_lifecycle) {
    ctx_tracker_t* t = ctx_tracker_create(16);
    ASSERT(t != NULL);
    ASSERT(ctx_tracker_count(t) == 0);

    ctx_result_t r = ctx_tracker_analyze(t);
    ASSERT(r.contamination_score == 0.0f);
    ASSERT(r.escalation_detected == 0);

    ctx_tracker_destroy(t);
}

TEST(test_tracker_recording_and_reset) {
    ctx_tracker_t* t = ctx_tracker_create(8);
    ASSERT(t != NULL);

    ctx_tracker_record(t, 0, 0.1f, 0, 1000.0);
    ctx_tracker_record(t, 1, 0.4f, 1, 2000.0);
    ASSERT(ctx_tracker_count(t) == 2);

    ctx_result_t r = ctx_tracker_analyze(t);
    ASSERT(r.total_suspicious == 1);
    ASSERT(r.total_malicious == 0);

    ctx_tracker_reset(t);
    ASSERT(ctx_tracker_count(t) == 0);
    ctx_tracker_destroy(t);
}

TEST(test_tracker_escalation_detection) {
    ctx_tracker_t* t = ctx_tracker_create(16);
    ASSERT(t != NULL);

    /* Record escalating threat scores */
    ctx_tracker_record(t, 0, 0.10f, 0, 1000000.0);
    ctx_tracker_record(t, 1, 0.35f, 1, 2000000.0);
    ctx_tracker_record(t, 1, 0.55f, 2, 3000000.0);
    ctx_tracker_record(t, 2, 0.85f, 3, 4000000.0);

    ctx_result_t r = ctx_tracker_analyze(t);
    ASSERT(r.escalation_detected == 1);
    ASSERT(r.contamination_score > 0.4f);
    ASSERT(r.suspicious_run_length >= 3);

    ctx_tracker_destroy(t);
}

TEST(test_tracker_benign_session) {
    ctx_tracker_t* t = ctx_tracker_create(16);
    ASSERT(t != NULL);

    for (int i = 0; i < 10; i++) {
        ctx_tracker_record(t, 0, 0.05f, 0, (double)(i * 1000000));
    }

    ctx_result_t r = ctx_tracker_analyze(t);
    ASSERT(r.escalation_detected == 0);
    ASSERT(r.contamination_score < 0.15f);
    ASSERT(r.total_malicious == 0);
    ASSERT(r.total_suspicious == 0);

    ctx_tracker_destroy(t);
}

int main(void) {
    printf("\n=== Context Tracker Unit Tests ===\n\n");

    RUN(test_tracker_lifecycle);
    RUN(test_tracker_recording_and_reset);
    RUN(test_tracker_escalation_detection);
    RUN(test_tracker_benign_session);

    printf("\n  %d/%d assertions passed\n\n", tests_passed, tests_total);
    return (tests_passed == tests_total) ? 0 : 1;
}
