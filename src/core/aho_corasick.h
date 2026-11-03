/*
 * PromptShield — Aho-Corasick Multi-Pattern Matcher
 * aho_corasick.h
 */

#ifndef PS_AHO_CORASICK_H
#define PS_AHO_CORASICK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ─────────────────────────────────────────────── */
#define AC_ALPHABET_SIZE  256       /* Byte-level matching */
#define AC_MAX_PATTERNS   512
#define AC_MAX_NODES      65536
#define AC_CATEGORY_LEN   64

/* ── Types ─────────────────────────────────────────────────── */

/** A single match found by the automaton */
typedef struct {
    uint32_t    pattern_id;
    uint32_t    position;               /* Byte offset in input */
    const char* pattern_text;
    char        category[AC_CATEGORY_LEN];
} ac_match_t;

/** Callback for reporting matches. Return 0 to continue, non-zero to stop. */
typedef int (*ac_match_cb)(const ac_match_t* match, void* user_data);

/** Opaque automaton handle */
typedef struct ac_automaton ac_automaton_t;

/* ── Lifecycle ─────────────────────────────────────────────── */

/** Create a new Aho-Corasick automaton. */
ac_automaton_t* ac_create(void);

/** Destroy the automaton and free all memory. */
void ac_destroy(ac_automaton_t* ac);

/* ── Pattern Loading ───────────────────────────────────────── */

/**
 * Add a pattern to the automaton (call before ac_compile).
 * @param ac        Automaton handle.
 * @param pattern   UTF-8 pattern string (case will be lowered internally).
 * @param len       Pattern length in bytes (0 = strlen).
 * @param category  Category tag (e.g., "instruction_override").
 * @return Pattern ID (>= 0), or -1 on error.
 */
int ac_add_pattern(ac_automaton_t* ac, const char* pattern, size_t len,
                   const char* category);

/** Get category string for a pattern ID. */
const char* ac_pattern_category(const ac_automaton_t* ac, int pattern_id);

/**
 * Load patterns from a JSON file (data/patterns.json format).
 * @return Number of patterns loaded, or -1 on error.
 */
int ac_load_patterns_json(ac_automaton_t* ac, const char* path);

/**
 * Compile the automaton (builds failure + output links).
 * Must be called after all patterns are added and before searching.
 * @return 0 on success, -1 on error.
 */
int ac_compile(ac_automaton_t* ac);

/* ── Searching ─────────────────────────────────────────────── */

/**
 * Search text for all matching patterns.
 * @param ac        Compiled automaton.
 * @param text      Input text (will be lowered for matching if case_insensitive).
 * @param len       Text length in bytes (0 = strlen).
 * @param matches   Output array for matches.
 * @param max_matches  Maximum matches to store.
 * @return Number of matches found.
 */
int ac_search(const ac_automaton_t* ac, const char* text, size_t len,
              ac_match_t* matches, int max_matches);

/**
 * Search with callback (for streaming / early exit).
 * @return Number of matches found, or -N if callback returned non-zero at match N.
 */
int ac_search_cb(const ac_automaton_t* ac, const char* text, size_t len,
                 ac_match_cb callback, void* user_data);

/**
 * Get the number of patterns loaded.
 */
int ac_pattern_count(const ac_automaton_t* ac);

#ifdef __cplusplus
}
#endif

#endif /* PS_AHO_CORASICK_H */
