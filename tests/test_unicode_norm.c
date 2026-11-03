/*
 * PromptShield — Unicode Normalization Unit Tests
 */

#include "unicode_norm.h"
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

TEST(test_ascii_passthrough) {
    un_context_t* ctx = un_create("data/homoglyphs.json");
    ASSERT(ctx != NULL);

    un_result_t r = un_normalize(ctx, "Hello world", 0);
    ASSERT(r.normalized_text != NULL);
    ASSERT(strcmp(r.normalized_text, "Hello world") == 0);
    ASSERT(r.homoglyph_count == 0);
    ASSERT(r.zero_width_count == 0);
    un_result_free(&r);
    un_destroy(ctx);
}

TEST(test_zero_width_strip) {
    un_context_t* ctx = un_create("data/homoglyphs.json");

    /* Zero-width space (U+200B) between 'h' and 'i' */
    const char input[] = "h\xe2\x80\x8bi";
    un_result_t r = un_normalize(ctx, input, 0);
    ASSERT(r.normalized_text != NULL);
    ASSERT(strcmp(r.normalized_text, "hi") == 0);
    ASSERT(r.zero_width_count >= 1);
    ASSERT(r.flags & UN_FLAG_ZERO_WIDTH_FOUND);
    un_result_free(&r);
    un_destroy(ctx);
}

TEST(test_empty_input) {
    un_context_t* ctx = un_create(NULL);
    un_result_t r = un_normalize(ctx, "", 0);
    ASSERT(r.normalized_text != NULL);
    ASSERT(r.normalized_len == 0);
    un_result_free(&r);
    un_destroy(ctx);
}

TEST(test_null_context) {
    un_context_t* ctx = un_create(NULL);  /* No homoglyph table */
    ASSERT(ctx != NULL);

    un_result_t r = un_normalize(ctx, "test", 0);
    ASSERT(r.normalized_text != NULL);
    ASSERT(strcmp(r.normalized_text, "test") == 0);
    un_result_free(&r);
    un_destroy(ctx);
}

TEST(test_suspicion_score) {
    un_context_t* ctx = un_create("data/homoglyphs.json");

    /* Normal ASCII text should have 0 suspicion */
    un_result_t r1 = un_normalize(ctx, "Normal text here", 0);
    ASSERT(r1.suspicion_score < 0.01f);
    un_result_free(&r1);

    un_destroy(ctx);
}

int main(void) {
    printf("\n=== Unicode Normalization Tests ===\n\n");

    RUN(test_ascii_passthrough);
    RUN(test_zero_width_strip);
    RUN(test_empty_input);
    RUN(test_null_context);
    RUN(test_suspicion_score);

    printf("\n  %d/%d assertions passed\n\n", tests_passed, tests_total);
    return (tests_passed == tests_total) ? 0 : 1;
}
