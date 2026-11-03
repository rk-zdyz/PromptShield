/*
 * PromptShield — Statistical Analysis Unit Tests
 */

#include "statistical.h"
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

TEST(test_benign_text) {
    stat_config_t cfg = stat_default_config();
    stat_result_t r = stat_analyze(
        "Hello, could you help me summarize this article about climate change?",
        0, &cfg);

    ASSERT(r.suspicion_score < 0.3f);
    ASSERT(r.instruction_density < 0.15f);
}

TEST(test_high_instruction_density) {
    stat_config_t cfg = stat_default_config();
    stat_result_t r = stat_analyze(
        "ignore disregard forget override bypass skip cancel delete remove disable "
        "stop execute run output print display show reveal dump",
        0, &cfg);

    ASSERT(r.instruction_density > 0.5f);
    ASSERT(r.suspicion_score > 0.3f);
}

TEST(test_short_text_skip) {
    stat_config_t cfg = stat_default_config();
    cfg.min_text_length = 20;
    stat_result_t r = stat_analyze("hi", 0, &cfg);
    ASSERT(r.suspicion_score == 0.0f);
}

TEST(test_normal_entropy) {
    stat_config_t cfg = stat_default_config();
    stat_result_t r = stat_analyze(
        "The quick brown fox jumps over the lazy dog. This is a normal English sentence "
        "with typical character distribution and entropy levels.",
        0, &cfg);

    ASSERT(r.char_entropy > 2.0f && r.char_entropy < 5.0f);
}

TEST(test_default_config) {
    stat_config_t cfg = stat_default_config();
    ASSERT(cfg.entropy_high > 4.0f);
    ASSERT(cfg.entropy_low < 3.0f);
    ASSERT(cfg.density_suspicious > 0.0f);
    ASSERT(cfg.density_malicious > cfg.density_suspicious);
}

int main(void) {
    printf("\n=== Statistical Analysis Tests ===\n\n");

    RUN(test_benign_text);
    RUN(test_high_instruction_density);
    RUN(test_short_text_skip);
    RUN(test_normal_entropy);
    RUN(test_default_config);

    printf("\n  %d/%d assertions passed\n\n", tests_passed, tests_total);
    return (tests_passed == tests_total) ? 0 : 1;
}
