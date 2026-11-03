/*
 * PromptShield — Shared Utilities
 * utils.c
 */

#include "utils.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <time.h>
#endif

/* ═══════════════════════════════════════════════════════════════
 * High-resolution timer
 * ═══════════════════════════════════════════════════════════════ */

double ps_time_us(void) {
#ifdef _WIN32
    static LARGE_INTEGER freq = {0};
    if (freq.QuadPart == 0) {
        QueryPerformanceFrequency(&freq);
    }
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1e6 / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
#endif
}

/* ═══════════════════════════════════════════════════════════════
 * File I/O
 * ═══════════════════════════════════════════════════════════════ */

char* ps_read_file(const char* path, size_t* out_len) {
    if (!path) return NULL;

    FILE* fp = fopen(path, "rb");
    if (!fp) return NULL;

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0) { fclose(fp); return NULL; }

    char* buf = (char*)malloc((size_t)fsize + 1);
    if (!buf) { fclose(fp); return NULL; }

    size_t n = fread(buf, 1, (size_t)fsize, fp);
    buf[n] = '\0';
    fclose(fp);

    if (out_len) *out_len = n;
    return buf;
}

/* ═══════════════════════════════════════════════════════════════
 * String utilities
 * ═══════════════════════════════════════════════════════════════ */

int ps_stricmp(const char* a, const char* b) {
    while (*a && *b) {
        int d = tolower((unsigned char)*a) - tolower((unsigned char)*b);
        if (d != 0) return d;
        a++; b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

void ps_strlcpy(char* dst, const char* src, size_t size) {
    if (size == 0) return;
    size_t i;
    for (i = 0; i < size - 1 && src[i]; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}
