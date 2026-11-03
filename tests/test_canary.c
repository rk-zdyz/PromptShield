/*
 * PromptShield — Canary Token Unit Tests
 */

#include "canary.h"
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

TEST(test_create_destroy) {
    canary_context_t* ctx = canary_create();
    ASSERT(ctx != NULL);
    ASSERT(canary_count(ctx) == 0);
    canary_destroy(ctx);
}

TEST(test_generate) {
    canary_context_t* ctx = canary_create();
    char buf[64];
    int len = canary_generate(ctx, buf, sizeof(buf));
    ASSERT(len > 0);
    ASSERT(strlen(buf) == (size_t)len);
    ASSERT(strstr(buf, "ps-canary-") != NULL);
    canary_destroy(ctx);
}

TEST(test_unique_canaries) {
    canary_context_t* ctx = canary_create();
    char buf1[64], buf2[64];
    canary_generate(ctx, buf1, sizeof(buf1));
    canary_generate(ctx, buf2, sizeof(buf2));
    ASSERT(strcmp(buf1, buf2) != 0);  /* Two canaries should differ */
    canary_destroy(ctx);
}

TEST(test_register_and_scan_found) {
    canary_context_t* ctx = canary_create();
    char canary[64];
    canary_generate(ctx, canary, sizeof(canary));
    canary_register(ctx, canary);

    /* Simulate LLM output that leaked the canary */
    char output[512];
    snprintf(output, sizeof(output),
             "Here is some normal output. %s And more text.", canary);

    canary_result_t r = canary_scan(ctx, output, 0);
    ASSERT(r.leaked == 1);
    ASSERT(r.leaked_count == 1);
    ASSERT(r.confidence == 1.0f);
    canary_destroy(ctx);
}

TEST(test_scan_not_found) {
    canary_context_t* ctx = canary_create();
    canary_register(ctx, "ps-canary-test123");

    canary_result_t r = canary_scan(ctx, "This is normal output with no tokens.", 0);
    ASSERT(r.leaked == 0);
    ASSERT(r.leaked_count == 0);
    ASSERT(r.confidence == 0.0f);
    canary_destroy(ctx);
}

TEST(test_clear) {
    canary_context_t* ctx = canary_create();
    canary_register(ctx, "token1");
    canary_register(ctx, "token2");
    ASSERT(canary_count(ctx) == 2);

    canary_clear(ctx);
    ASSERT(canary_count(ctx) == 0);
    canary_destroy(ctx);
}

int main(void) {
    printf("\n=== Canary Token Tests ===\n\n");

    RUN(test_create_destroy);
    RUN(test_generate);
    RUN(test_unique_canaries);
    RUN(test_register_and_scan_found);
    RUN(test_scan_not_found);
    RUN(test_clear);

    printf("\n  %d/%d assertions passed\n\n", tests_passed, tests_total);
    return (tests_passed == tests_total) ? 0 : 1;
}
