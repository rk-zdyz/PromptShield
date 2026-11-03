/*
 * PromptShield — Unicode Normalization + Homoglyph Resolution
 * unicode_norm.c
 *
 * Self-contained implementation (no ICU dependency).
 * Handles: fullwidth→ASCII, Cyrillic/Greek homoglyphs→Latin,
 * zero-width character stripping, and mixed-script detection.
 */

#include "unicode_norm.h"
#include "cJSON.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ═══════════════════════════════════════════════════════════════
 * Internal: Homoglyph mapping table (hash map)
 * ═══════════════════════════════════════════════════════════════ */

#define HOMO_MAP_SIZE 1024

typedef struct homo_entry {
    uint32_t            codepoint;
    char                replacement[8];     /* UTF-8 replacement (typically 1 ASCII byte) */
    uint8_t             rep_len;
    struct homo_entry*  next;               /* Chaining for collisions */
} homo_entry_t;

struct un_context {
    homo_entry_t*   buckets[HOMO_MAP_SIZE];
    int             entry_count;
};

/* ── Hash function ────────────────────────────────────────────── */
static uint32_t homo_hash(uint32_t cp) {
    return cp % HOMO_MAP_SIZE;
}

/* ── Insert into hash map ─────────────────────────────────────── */
static void homo_insert(un_context_t* ctx, uint32_t codepoint,
                        const char* replacement, size_t rep_len) {
    uint32_t h = homo_hash(codepoint);
    homo_entry_t* e = (homo_entry_t*)malloc(sizeof(homo_entry_t));
    if (!e) return;

    e->codepoint = codepoint;
    if (rep_len > 7) rep_len = 7;
    memcpy(e->replacement, replacement, rep_len);
    e->replacement[rep_len] = '\0';
    e->rep_len = (uint8_t)rep_len;
    e->next = ctx->buckets[h];
    ctx->buckets[h] = e;
    ctx->entry_count++;
}

/* ── Lookup in hash map ───────────────────────────────────────── */
static const homo_entry_t* homo_lookup(const un_context_t* ctx, uint32_t codepoint) {
    uint32_t h = homo_hash(codepoint);
    const homo_entry_t* e = ctx->buckets[h];
    while (e) {
        if (e->codepoint == codepoint) return e;
        e = e->next;
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════
 * UTF-8 codec helpers
 * ═══════════════════════════════════════════════════════════════ */

/** Decode a single UTF-8 codepoint. Returns bytes consumed, 0 on error. */
static int utf8_decode(const char* s, size_t remaining, uint32_t* out_cp) {
    if (remaining == 0) return 0;
    unsigned char b0 = (unsigned char)s[0];

    if (b0 < 0x80) {
        *out_cp = b0;
        return 1;
    } else if ((b0 & 0xE0) == 0xC0 && remaining >= 2) {
        *out_cp = ((uint32_t)(b0 & 0x1F) << 6) |
                  ((uint32_t)(s[1] & 0x3F));
        return 2;
    } else if ((b0 & 0xF0) == 0xE0 && remaining >= 3) {
        *out_cp = ((uint32_t)(b0 & 0x0F) << 12) |
                  ((uint32_t)(s[1] & 0x3F) << 6)  |
                  ((uint32_t)(s[2] & 0x3F));
        return 3;
    } else if ((b0 & 0xF8) == 0xF0 && remaining >= 4) {
        *out_cp = ((uint32_t)(b0 & 0x07) << 18) |
                  ((uint32_t)(s[1] & 0x3F) << 12) |
                  ((uint32_t)(s[2] & 0x3F) << 6)  |
                  ((uint32_t)(s[3] & 0x3F));
        return 4;
    }

    /* Invalid sequence: skip one byte */
    *out_cp = 0xFFFD;
    return 1;
}

/** Encode a codepoint to UTF-8. Returns bytes written. */
static int utf8_encode(uint32_t cp, char* out) {
    if (cp < 0x80) {
        out[0] = (char)cp;
        return 1;
    } else if (cp < 0x800) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    } else if (cp < 0x10000) {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    } else {
        out[0] = (char)(0xF0 | (cp >> 18));
        out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[3] = (char)(0x80 | (cp & 0x3F));
        return 4;
    }
}

/* ═══════════════════════════════════════════════════════════════
 * Script detection
 * ═══════════════════════════════════════════════════════════════ */

typedef enum {
    SCRIPT_UNKNOWN = 0,
    SCRIPT_LATIN,
    SCRIPT_CYRILLIC,
    SCRIPT_GREEK,
    SCRIPT_COMMON
} script_t;

static script_t detect_script(uint32_t cp) {
    if (cp < 0x80) return SCRIPT_LATIN;
    if (cp >= 0x0041 && cp <= 0x024F) return SCRIPT_LATIN;
    if (cp >= 0x0400 && cp <= 0x04FF) return SCRIPT_CYRILLIC;
    if (cp >= 0x0500 && cp <= 0x052F) return SCRIPT_CYRILLIC;
    if (cp >= 0x0370 && cp <= 0x03FF) return SCRIPT_GREEK;
    if (cp >= 0x1F00 && cp <= 0x1FFF) return SCRIPT_GREEK;
    /* Common (punctuation, whitespace, etc.) */
    if (cp < 0x0041) return SCRIPT_COMMON;
    return SCRIPT_UNKNOWN;
}

/* ═══════════════════════════════════════════════════════════════
 * Zero-width / invisible character detection
 * ═══════════════════════════════════════════════════════════════ */

static int is_zero_width(uint32_t cp) {
    return (cp == 0x200B ||   /* Zero Width Space */
            cp == 0x200C ||   /* Zero Width Non-Joiner */
            cp == 0x200D ||   /* Zero Width Joiner */
            cp == 0xFEFF ||   /* BOM / Zero Width No-Break Space */
            cp == 0x00AD ||   /* Soft Hyphen */
            cp == 0x034F ||   /* Combining Grapheme Joiner */
            cp == 0x061C ||   /* Arabic Letter Mark */
            cp == 0x115F ||   /* Hangul Choseong Filler */
            cp == 0x1160 ||   /* Hangul Jungseong Filler */
            cp == 0x17B4 ||   /* Khmer Vowel Inherent Aq */
            cp == 0x17B5 ||   /* Khmer Vowel Inherent Aa */
            (cp >= 0x180B && cp <= 0x180E) ||  /* Mongolian free variation */
            (cp >= 0x2060 && cp <= 0x2064) ||  /* Word joiner etc */
            (cp >= 0x2066 && cp <= 0x2069) ||  /* Bidi isolates */
            (cp >= 0x202A && cp <= 0x202E) ||  /* Bidi embedding */
            cp == 0x2800 ||   /* Braille blank */
            (cp >= 0xFE00 && cp <= 0xFE0F) ||  /* Variation selectors */
            (cp >= 0xE0100 && cp <= 0xE01EF)); /* VS17-VS256 */
}

/* ═══════════════════════════════════════════════════════════════
 * JSON parsing for homoglyph table
 * ═══════════════════════════════════════════════════════════════ */

/** Parse a hex escape or literal UTF-8 key into a codepoint */
static uint32_t parse_json_key_to_codepoint(const char* key) {
    /* The JSON keys are the actual Unicode characters (UTF-8 encoded) */
    uint32_t cp = 0;
    utf8_decode(key, strlen(key), &cp);
    return cp;
}

static int load_mapping_group(un_context_t* ctx, cJSON* group) {
    int count = 0;
    cJSON* entry = NULL;
    cJSON_ArrayForEach(entry, group) {
        if (!cJSON_IsString(entry)) continue;

        const char* key = entry->string;
        const char* val = entry->valuestring;

        uint32_t cp = parse_json_key_to_codepoint(key);
        if (cp == 0 || cp == 0xFFFD) continue;

        size_t val_len = strlen(val);
        homo_insert(ctx, cp, val, val_len);
        count++;
    }
    return count;
}

/* ═══════════════════════════════════════════════════════════════
 * Lifecycle
 * ═══════════════════════════════════════════════════════════════ */

un_context_t* un_create(const char* homoglyphs_json_path) {
    un_context_t* ctx = (un_context_t*)calloc(1, sizeof(un_context_t));
    if (!ctx) return NULL;

    if (!homoglyphs_json_path) return ctx;  /* No table, just strip zero-width */

    /* Read file */
    FILE* fp = fopen(homoglyphs_json_path, "rb");
    if (!fp) return ctx;  /* Graceful: work without table */

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char* json_str = (char*)malloc((size_t)fsize + 1);
    if (!json_str) { fclose(fp); return ctx; }

    size_t read_n = fread(json_str, 1, (size_t)fsize, fp);
    json_str[read_n] = '\0';
    fclose(fp);

    cJSON* root = cJSON_Parse(json_str);
    free(json_str);
    if (!root) return ctx;

    cJSON* mappings = cJSON_GetObjectItem(root, "mappings");
    if (mappings) {
        /* Load each mapping group */
        cJSON* group = NULL;
        cJSON_ArrayForEach(group, mappings) {
            load_mapping_group(ctx, group);
        }
    }

    cJSON_Delete(root);
    return ctx;
}

void un_destroy(un_context_t* ctx) {
    if (!ctx) return;
    for (int i = 0; i < HOMO_MAP_SIZE; i++) {
        homo_entry_t* e = ctx->buckets[i];
        while (e) {
            homo_entry_t* next = e->next;
            free(e);
            e = next;
        }
    }
    free(ctx);
}

/* ═══════════════════════════════════════════════════════════════
 * Normalization
 * ═══════════════════════════════════════════════════════════════ */

un_result_t un_normalize(const un_context_t* ctx, const char* text, size_t len) {
    un_result_t result;
    memset(&result, 0, sizeof(result));

    if (!text) return result;
    if (len == 0) len = strlen(text);
    if (len == 0) {
        result.normalized_text = (char*)calloc(1, 1);
        return result;
    }

    /* Allocate output (worst case: same size as input) */
    char* out = (char*)malloc(len * 4 + 1);  /* Extra room for expansions */
    if (!out) return result;

    size_t out_pos = 0;
    uint32_t scripts_seen = 0;   /* Bitmask of scripts encountered */
    int has_latin = 0;

    size_t i = 0;
    while (i < len) {
        uint32_t cp;
        int bytes = utf8_decode(text + i, len - i, &cp);
        if (bytes == 0) break;

        /* Track scripts for mixed-script detection */
        script_t sc = detect_script(cp);
        if (sc == SCRIPT_LATIN)    has_latin = 1;
        if (sc != SCRIPT_COMMON && sc != SCRIPT_UNKNOWN)
            scripts_seen |= (1u << sc);

        /* Check for zero-width characters → strip them */
        if (is_zero_width(cp)) {
            result.zero_width_count++;
            result.flags |= UN_FLAG_ZERO_WIDTH_FOUND;
            if (cp == 0x200B || cp == 0x200C || cp == 0x200D || cp == 0xFEFF)
                result.flags |= UN_FLAG_INVISIBLE_CHARS;
            i += (size_t)bytes;
            continue;
        }

        /* Check homoglyph table */
        const homo_entry_t* mapping = ctx ? homo_lookup(ctx, cp) : NULL;

        if (mapping) {
            /* Replace with ASCII equivalent */
            memcpy(out + out_pos, mapping->replacement, mapping->rep_len);
            out_pos += mapping->rep_len;
            result.homoglyph_count++;

            /* Flag specific types */
            if (cp >= 0xFF01 && cp <= 0xFF5E)
                result.flags |= UN_FLAG_FULLWIDTH_FOUND;
            else
                result.flags |= UN_FLAG_HOMOGLYPHS_FOUND;
        } else {
            /* Pass through unchanged */
            memcpy(out + out_pos, text + i, (size_t)bytes);
            out_pos += (size_t)bytes;
        }

        i += (size_t)bytes;
    }

    out[out_pos] = '\0';

    /* Check for mixed scripts (Latin + Cyrillic or Latin + Greek = suspicious) */
    if (has_latin) {
        int non_latin_scripts = 0;
        for (int s = 2; s <= 4; s++) {   /* CYRILLIC=2, GREEK=3 */
            if (scripts_seen & (1u << s)) non_latin_scripts++;
        }
        if (non_latin_scripts > 0)
            result.flags |= UN_FLAG_MIXED_SCRIPT;
    }

    /* Compute suspicion score */
    if (len > 0) {
        float homo_ratio = (float)result.homoglyph_count / (float)len;
        float zw_ratio   = (float)result.zero_width_count / (float)len;
        float mixed      = (result.flags & UN_FLAG_MIXED_SCRIPT) ? 0.3f : 0.0f;

        result.suspicion_score = homo_ratio * 2.0f + zw_ratio * 3.0f + mixed;
        if (result.suspicion_score > 1.0f) result.suspicion_score = 1.0f;
    }

    result.normalized_text = out;
    result.normalized_len  = out_pos;

    return result;
}

void un_result_free(un_result_t* result) {
    if (result && result->normalized_text) {
        free(result->normalized_text);
        result->normalized_text = NULL;
    }
}

/* ═══════════════════════════════════════════════════════════════
 * G2: Encoding Evasion — Deobfuscation Pass
 *
 * Addresses Research Gap G2 from Greshake et al. §5.2:
 * Detects and decodes encoded payloads that bypass pattern matching.
 * ═══════════════════════════════════════════════════════════════ */

/* ── Base64 helpers ───────────────────────────────────────────── */

static const int B64_DECODE_TABLE[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

static int is_base64_char(unsigned char c) {
    return B64_DECODE_TABLE[c] >= 0 || c == '=';
}

/**
 * Check if a substring looks like base64: [A-Za-z0-9+/=]{20,}
 * and try to decode it. Returns decoded length, or 0 on failure.
 */
static size_t try_base64_decode(const char* src, size_t src_len,
                                 char* out, size_t out_cap) {
    if (src_len < 20) return 0;
    if (src_len % 4 != 0) return 0;

    size_t out_len = 0;
    for (size_t i = 0; i < src_len; i += 4) {
        int a = B64_DECODE_TABLE[(unsigned char)src[i]];
        int b = B64_DECODE_TABLE[(unsigned char)src[i+1]];
        int c = B64_DECODE_TABLE[(unsigned char)src[i+2]];
        int d = B64_DECODE_TABLE[(unsigned char)src[i+3]];

        if (a < 0 || b < 0) return 0;  /* Invalid */

        if (out_len < out_cap)
            out[out_len++] = (char)((a << 2) | (b >> 4));

        if (c >= 0) {
            if (out_len < out_cap)
                out[out_len++] = (char)(((b & 0x0F) << 4) | (c >> 2));
            if (d >= 0) {
                if (out_len < out_cap)
                    out[out_len++] = (char)(((c & 0x03) << 6) | d);
            }
        }
    }

    /* Check if decoded content looks like printable text */
    int printable = 0;
    for (size_t i = 0; i < out_len; i++) {
        unsigned char ch = (unsigned char)out[i];
        if (ch >= 0x20 && ch < 0x7F) printable++;
    }
    /* At least 70% printable to be considered text */
    if (out_len > 0 && (printable * 100 / (int)out_len) < 70) return 0;

    return out_len;
}

/* ── URL decode helper ────────────────────────────────────────── */

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t url_decode(const char* src, size_t len,
                          char* out, size_t out_cap, uint32_t* decode_count) {
    size_t out_len = 0;
    *decode_count = 0;
    for (size_t i = 0; i < len && out_len < out_cap; ) {
        if (src[i] == '%' && i + 2 < len) {
            int h = hex_val(src[i+1]);
            int l = hex_val(src[i+2]);
            if (h >= 0 && l >= 0) {
                out[out_len++] = (char)((h << 4) | l);
                (*decode_count)++;
                i += 3;
                continue;
            }
        }
        if (src[i] == '+') {
            out[out_len++] = ' ';
            (*decode_count)++;
            i++;
        } else {
            out[out_len++] = src[i++];
        }
    }
    return out_len;
}

/* ── Leetspeak normalization ──────────────────────────────────── */

static char leet_to_ascii(char c) {
    switch (c) {
        case '0': return 'o';
        case '1': return 'i';
        case '3': return 'e';
        case '4': return 'a';
        case '5': return 's';
        case '7': return 't';
        case '@': return 'a';
        case '!': return 'i';
        case '$': return 's';
        case '(': return 'c';
        default:  return 0;
    }
}

static size_t normalize_leetspeak(const char* src, size_t len,
                                   char* out, size_t out_cap,
                                   uint32_t* leet_count) {
    size_t out_len = 0;
    *leet_count = 0;
    int in_word = 0;
    int has_alpha = 0;
    int has_leet = 0;

    /* Two-pass: first check if word has mixed alpha+leet, then normalize */
    for (size_t i = 0; i < len && out_len < out_cap; i++) {
        char c = src[i];
        char leet = leet_to_ascii(c);

        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
            in_word = 1;
            has_alpha = 1;
            out[out_len++] = c;
        } else if (leet && in_word) {
            /* In a word context, substitute leet char */
            has_leet = 1;
            out[out_len++] = leet;
            (*leet_count)++;
        } else if (leet && !in_word) {
            /* Start of potential leet word */
            in_word = 1;
            has_leet = 1;
            out[out_len++] = leet;
            (*leet_count)++;
        } else {
            in_word = 0;
            has_alpha = 0;
            has_leet = 0;
            out[out_len++] = c;
        }
    }

    (void)has_alpha;
    (void)has_leet;
    return out_len;
}

/* ── HTML entity decode ───────────────────────────────────────── */

typedef struct { const char* entity; char replacement; } html_entity_map_t;

static const html_entity_map_t HTML_ENTITIES[] = {
    {"&lt;",    '<'},  {"&gt;",    '>'},  {"&amp;",   '&'},
    {"&quot;",  '"'},  {"&apos;",  '\''}, {"&nbsp;",  ' '},
    {"&semi;",  ';'},  {"&colon;", ':'},  {"&comma;", ','},
    {"&period;",'.'}, {"&excl;",  '!'},  {"&quest;", '?'},
    {"&sol;",   '/'},  {"&bsol;",  '\\'}, {"&lpar;",  '('},
    {"&rpar;",  ')'},  {"&lsqb;",  '['},  {"&rsqb;",  ']'},
    {"&lcub;",  '{'},  {"&rcub;",  '}'},  {"&equals;",'='},
    {"&plus;",  '+'},  {"&hyphen;",'-'},  {"&ast;",   '*'},
    {"&num;",   '#'},  {"&percnt;",'%'},  {"&dollar;",'$'},
    {"&commat;",'@'},  {"&Hat;",   '^'},  {"&lowbar;",'_'},
    {"&vert;",  '|'},  {"&tilde;", '~'},
    {NULL, 0}
};

static size_t html_entity_decode(const char* src, size_t len,
                                  char* out, size_t out_cap,
                                  uint32_t* entity_count) {
    size_t out_len = 0;
    *entity_count = 0;

    for (size_t i = 0; i < len && out_len < out_cap; ) {
        if (src[i] == '&') {
            int found = 0;

            /* Try &#xHH; hex numeric reference */
            if (i + 4 < len && src[i+1] == '#' && src[i+2] == 'x') {
                size_t j = i + 3;
                int val = 0;
                while (j < len && j < i + 7 && src[j] != ';') {
                    int h = hex_val(src[j]);
                    if (h < 0) break;
                    val = val * 16 + h;
                    j++;
                }
                if (j < len && src[j] == ';' && val > 0 && val < 128) {
                    out[out_len++] = (char)val;
                    (*entity_count)++;
                    i = j + 1;
                    continue;
                }
            }

            /* Try &#DDD; decimal numeric reference */
            if (i + 3 < len && src[i+1] == '#' && src[i+2] >= '0' && src[i+2] <= '9') {
                size_t j = i + 2;
                int val = 0;
                while (j < len && j < i + 6 && src[j] != ';') {
                    if (src[j] < '0' || src[j] > '9') break;
                    val = val * 10 + (src[j] - '0');
                    j++;
                }
                if (j < len && src[j] == ';' && val > 0 && val < 128) {
                    out[out_len++] = (char)val;
                    (*entity_count)++;
                    i = j + 1;
                    continue;
                }
            }

            /* Try named entities */
            for (int k = 0; HTML_ENTITIES[k].entity != NULL; k++) {
                size_t elen = strlen(HTML_ENTITIES[k].entity);
                if (i + elen <= len &&
                    memcmp(src + i, HTML_ENTITIES[k].entity, elen) == 0) {
                    out[out_len++] = HTML_ENTITIES[k].replacement;
                    (*entity_count)++;
                    i += elen;
                    found = 1;
                    break;
                }
            }
            if (!found) {
                out[out_len++] = src[i++];
            }
        } else {
            out[out_len++] = src[i++];
        }
    }
    return out_len;
}

/* ═══════════════════════════════════════════════════════════════
 * Main deobfuscation entry point (G2)
 * ═══════════════════════════════════════════════════════════════ */

char* un_deobfuscate(const char* text, size_t len, un_result_t* result) {
    if (!text) return NULL;
    if (len == 0) len = strlen(text);
    if (len == 0) return NULL;

    /* Allocate working buffers (generous sizes) */
    size_t buf_size = len * 4 + 256;
    char* buf1 = (char*)malloc(buf_size);
    char* buf2 = (char*)malloc(buf_size);
    if (!buf1 || !buf2) { free(buf1); free(buf2); return NULL; }

    /* Pass 1: URL decode */
    uint32_t url_count = 0;
    size_t cur_len = url_decode(text, len, buf1, buf_size - 1, &url_count);
    buf1[cur_len] = '\0';
    if (result && url_count > 0) {
        result->url_decode_count = url_count;
        result->flags |= UN_FLAG_URL_ENCODED_FOUND;
    }

    /* Pass 2: HTML entity decode */
    uint32_t html_count = 0;
    cur_len = html_entity_decode(buf1, cur_len, buf2, buf_size - 1, &html_count);
    buf2[cur_len] = '\0';
    if (result && html_count > 0) {
        result->html_entity_count = html_count;
        result->flags |= UN_FLAG_HTML_ENTITY_FOUND;
    }

    /* Pass 3: Base64 segment detection and inline decode (before leetspeak so b64 digits aren't mutated) */
    size_t mid_len = 0;
    char* b64_out = buf1;
    size_t i = 0;
    while (i < cur_len) {
        /* Look for a run of base64 chars */
        size_t start = i;
        while (i < cur_len && is_base64_char((unsigned char)buf2[i])) i++;
        size_t run_len = i - start;

        if (run_len >= 16 && (run_len % 4) == 0) {
            /* Try to decode */
            char decoded[4096];
            size_t dec_len = try_base64_decode(buf2 + start, run_len,
                                                decoded, sizeof(decoded) - 1);
            if (dec_len > 0) {
                decoded[dec_len] = '\0';
                /* Insert decoded text (with space separators) */
                if (mid_len > 0 && mid_len < buf_size - 1)
                    b64_out[mid_len++] = ' ';
                for (size_t j = 0; j < dec_len && mid_len < buf_size - 1; j++)
                    b64_out[mid_len++] = decoded[j];
                if (mid_len < buf_size - 1)
                    b64_out[mid_len++] = ' ';
                if (result) {
                    result->base64_segments++;
                    result->flags |= UN_FLAG_BASE64_FOUND;
                }
                continue;
            }
        }

        /* Copy non-base64 content through */
        for (size_t j = start; j < i && mid_len < buf_size - 1; j++)
            b64_out[mid_len++] = buf2[j];

        /* Copy non-base64 char that terminated the run */
        if (i < cur_len && mid_len < buf_size - 1)
            b64_out[mid_len++] = buf2[i++];
    }
    b64_out[mid_len] = '\0';

    /* Pass 4: Leetspeak normalization */
    uint32_t leet_count = 0;
    size_t final_len = normalize_leetspeak(buf1, mid_len, buf2, buf_size - 1, &leet_count);
    buf2[final_len] = '\0';
    char* final = buf2;
    if (result && leet_count > 0) {
        result->leet_replacements = leet_count;
        result->flags |= UN_FLAG_LEETSPEAK_FOUND;
    }

    /* Update suspicion score based on deobfuscation findings */
    if (result) {
        float deob_score = 0.0f;
        if (result->base64_segments > 0) deob_score += 0.4f;
        if (result->url_decode_count > 3) deob_score += 0.2f;
        if (result->leet_replacements > 3) deob_score += 0.15f;
        if (result->html_entity_count > 3) deob_score += 0.2f;

        if (deob_score > 0.0f) {
            result->suspicion_score += deob_score;
            if (result->suspicion_score > 1.0f)
                result->suspicion_score = 1.0f;
        }
    }

    /* Return the final buffer, free the other */
    char* output = (char*)malloc(final_len + 1);
    if (output) {
        memcpy(output, final, final_len);
        output[final_len] = '\0';
    }
    free(buf1);
    free(buf2);
    return output;
}

