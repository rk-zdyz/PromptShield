/*
 * PromptShield — Canary Token Detection
 * canary.c
 *
 * Generates high-entropy, unique sentinel strings and scans LLM output
 * for their presence (indicating prompt/system-prompt leakage).
 */

#include "canary.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

/* ═══════════════════════════════════════════════════════════════
 * Internal types
 * ═══════════════════════════════════════════════════════════════ */

struct canary_context {
    char    tokens[CANARY_MAX_TOKENS][CANARY_TOKEN_LEN];
    int     count;
    int     seeded;
};

/* ═══════════════════════════════════════════════════════════════
 * Random byte generation (cross-platform)
 * ═══════════════════════════════════════════════════════════════ */

static int fill_random_bytes(unsigned char* buf, size_t len) {
#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL,
                               CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        return -1;
    }
    BOOL ok = CryptGenRandom(hProv, (DWORD)len, buf);
    CryptReleaseContext(hProv, 0);
    return ok ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, len);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
#endif
}

/* ═══════════════════════════════════════════════════════════════
 * Lifecycle
 * ═══════════════════════════════════════════════════════════════ */

canary_context_t* canary_create(void) {
    canary_context_t* ctx = (canary_context_t*)calloc(1, sizeof(canary_context_t));
    return ctx;
}

void canary_destroy(canary_context_t* ctx) {
    if (ctx) {
        /* Zero out tokens for security */
        memset(ctx->tokens, 0, sizeof(ctx->tokens));
        free(ctx);
    }
}

/* ═══════════════════════════════════════════════════════════════
 * Token generation
 * ═══════════════════════════════════════════════════════════════ */

int canary_generate(canary_context_t* ctx, char* buf, size_t size) {
    if (!ctx || !buf || size < CANARY_TOKEN_LEN) return -1;

    /* Generate 16 random bytes → 32 hex chars */
    unsigned char random_bytes[16];
    if (fill_random_bytes(random_bytes, sizeof(random_bytes)) != 0) {
        /* Fallback to time-based seeding (less secure but functional) */
        if (!ctx->seeded) {
            srand((unsigned int)time(NULL) ^ (unsigned int)(size_t)ctx);
            ctx->seeded = 1;
        }
        for (int i = 0; i < 16; i++) {
            random_bytes[i] = (unsigned char)(rand() & 0xFF);
        }
    }

    /* Format: «ps-canary-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX» */
    static const char hex[] = "0123456789abcdef";
    int pos = snprintf(buf, size, "\xc2\xab" "ps-canary-");  /* « prefix */

    for (int i = 0; i < 16 && pos + 2 < (int)size; i++) {
        buf[pos++] = hex[random_bytes[i] >> 4];
        buf[pos++] = hex[random_bytes[i] & 0x0F];
    }

    /* » suffix */
    if (pos + 2 < (int)size) {
        buf[pos++] = '\xc2';
        buf[pos++] = '\xbb';
    }
    buf[pos] = '\0';

    return pos;
}

/* ═══════════════════════════════════════════════════════════════
 * Registration
 * ═══════════════════════════════════════════════════════════════ */

int canary_register(canary_context_t* ctx, const char* token) {
    if (!ctx || !token) return -1;
    if (ctx->count >= CANARY_MAX_TOKENS) return -1;

    size_t len = strlen(token);
    if (len == 0 || len >= CANARY_TOKEN_LEN) return -1;

    strncpy(ctx->tokens[ctx->count], token, CANARY_TOKEN_LEN - 1);
    ctx->tokens[ctx->count][CANARY_TOKEN_LEN - 1] = '\0';

    return ctx->count++;
}

/* ═══════════════════════════════════════════════════════════════
 * Scanning
 * ═══════════════════════════════════════════════════════════════ */

canary_result_t canary_scan(const canary_context_t* ctx, const char* text, size_t len) {
    canary_result_t r;
    memset(&r, 0, sizeof(r));

    if (!ctx || !text || ctx->count == 0) {
        snprintf(r.details, sizeof(r.details), "No canaries registered");
        return r;
    }

    if (len == 0) len = strlen(text);

    for (int i = 0; i < ctx->count; i++) {
        const char* tok = ctx->tokens[i];
        size_t tok_len = strlen(tok);
        if (tok_len == 0) continue;

        /* Simple substring search (canaries are short, text may be long) */
        if (tok_len <= len) {
            for (size_t j = 0; j <= len - tok_len; j++) {
                if (memcmp(text + j, tok, tok_len) == 0) {
                    r.leaked = 1;
                    if (r.leaked_count < CANARY_MAX_TOKENS) {
                        r.leaked_indices[r.leaked_count] = i;
                    }
                    r.leaked_count++;
                    break;  /* Found this canary, move to next */
                }
            }
        }
    }

    r.confidence = r.leaked ? 1.0f : 0.0f;

    if (r.leaked) {
        snprintf(r.details, sizeof(r.details),
                 "CANARY LEAKAGE: %d canary token(s) found in output", r.leaked_count);
    } else {
        snprintf(r.details, sizeof(r.details), "No canary leakage detected");
    }

    return r;
}

void canary_clear(canary_context_t* ctx) {
    if (!ctx) return;
    memset(ctx->tokens, 0, sizeof(ctx->tokens));
    ctx->count = 0;
}

int canary_count(const canary_context_t* ctx) {
    return ctx ? ctx->count : 0;
}
