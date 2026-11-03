/*
 * PromptShield — Shared Utilities
 * utils.h
 */

#ifndef PS_UTILS_H
#define PS_UTILS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── High-resolution timer ────────────────────────────────────── */

/** Get current time in microseconds (monotonic). */
double ps_time_us(void);

/* ── File I/O ─────────────────────────────────────────────────── */

/** Read an entire file into a malloc'd buffer. Returns NULL on error. */
char* ps_read_file(const char* path, size_t* out_len);

/* ── String utilities ─────────────────────────────────────────── */

/** Portable case-insensitive string comparison */
int ps_stricmp(const char* a, const char* b);

/** Safe string copy with guaranteed null-termination */
void ps_strlcpy(char* dst, const char* src, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* PS_UTILS_H */
