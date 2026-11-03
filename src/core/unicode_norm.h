/*
 * PromptShield — Unicode Normalization + Homoglyph Resolution
 * unicode_norm.h
 */

#ifndef PS_UNICODE_NORM_H
#define PS_UNICODE_NORM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Normalization result flags */
#define UN_FLAG_HOMOGLYPHS_FOUND    (1u << 0)
#define UN_FLAG_MIXED_SCRIPT        (1u << 1)
#define UN_FLAG_FULLWIDTH_FOUND     (1u << 2)
#define UN_FLAG_ZERO_WIDTH_FOUND    (1u << 3)
#define UN_FLAG_INVISIBLE_CHARS     (1u << 4)
#define UN_FLAG_BASE64_FOUND        (1u << 5)
#define UN_FLAG_URL_ENCODED_FOUND   (1u << 6)
#define UN_FLAG_LEETSPEAK_FOUND     (1u << 7)
#define UN_FLAG_HTML_ENTITY_FOUND   (1u << 8)

/** Result from normalization */
typedef struct {
    char*       normalized_text;    /* Heap-allocated, caller must free */
    size_t      normalized_len;
    uint32_t    flags;              /* Bitmask of UN_FLAG_* */
    uint32_t    homoglyph_count;    /* Number of characters replaced */
    uint32_t    zero_width_count;   /* Number of zero-width chars removed */
    uint32_t    base64_segments;    /* Number of base64 segments decoded (G2) */
    uint32_t    url_decode_count;   /* Number of URL-encoded sequences decoded (G2) */
    uint32_t    leet_replacements;  /* Number of leetspeak chars normalized (G2) */
    uint32_t    html_entity_count;  /* Number of HTML entities decoded (G2) */
    float       suspicion_score;    /* 0.0 — 1.0 based on deobfuscation */
} un_result_t;

/** Opaque handle for normalization tables */
typedef struct un_context un_context_t;

/** Create a normalization context, loading homoglyph tables from JSON. */
un_context_t* un_create(const char* homoglyphs_json_path);

/** Destroy the context. */
void un_destroy(un_context_t* ctx);

/**
 * Normalize text: apply homoglyph resolution, strip zero-width chars,
 * convert fullwidth to ASCII.
 * @param ctx   Context with loaded tables.
 * @param text  Input UTF-8 text.
 * @param len   Length in bytes (0 = strlen).
 * @return Result with normalized text (caller must free normalized_text).
 */
un_result_t un_normalize(const un_context_t* ctx, const char* text, size_t len);

/**
 * Deobfuscation pass (G2): decode base64 segments, URL-encoded sequences,
 * leetspeak substitutions, and HTML entities within the text.
 * @param text  Input text (typically output of un_normalize).
 * @param len   Length in bytes (0 = strlen).
 * @param result  un_result_t to update with deobfuscation counts/flags.
 * @return Heap-allocated deobfuscated text (caller must free), or NULL.
 */
char* un_deobfuscate(const char* text, size_t len, un_result_t* result);

/** Free the normalized text in a result. */
void un_result_free(un_result_t* result);

#ifdef __cplusplus
}
#endif

#endif /* PS_UNICODE_NORM_H */
