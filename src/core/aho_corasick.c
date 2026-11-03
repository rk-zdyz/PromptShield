/*
 * PromptShield — Aho-Corasick Multi-Pattern Matcher
 * aho_corasick.c
 *
 * Full automaton: trie construction, BFS failure-link computation,
 * output-link chaining, and O(n + m + z) text search.
 */

#include "aho_corasick.h"
#include "cJSON.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* ═══════════════════════════════════════════════════════════════
 * Internal types
 * ═══════════════════════════════════════════════════════════════ */

/** A single trie node */
typedef struct {
    int     children[AC_ALPHABET_SIZE];   /* Index into node pool, -1 = none */
    int     failure;                       /* Failure link (longest proper suffix) */
    int     output;                        /* Output link (next pattern-ending state) */
    int     pattern_id;                    /* >= 0 if this node terminates a pattern */
    int     depth;                         /* Depth in trie */
} ac_node_t;

/** A stored pattern entry */
typedef struct {
    char*       text;
    size_t      len;
    char        category[AC_CATEGORY_LEN];
} ac_pattern_entry_t;

/** The automaton */
struct ac_automaton {
    ac_node_t           nodes[AC_MAX_NODES];
    int                 node_count;

    ac_pattern_entry_t  patterns[AC_MAX_PATTERNS];
    int                 pattern_count;

    int                 compiled;
};

/* ═══════════════════════════════════════════════════════════════
 * Helpers
 * ═══════════════════════════════════════════════════════════════ */

static void node_init(ac_node_t* n) {
    memset(n->children, -1, sizeof(n->children));
    n->failure    = 0;
    n->output     = -1;
    n->pattern_id = -1;
    n->depth      = 0;
}

static char to_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

/* Simple queue for BFS (used during compile) */
typedef struct {
    int     data[AC_MAX_NODES];
    int     head;
    int     tail;
} bfs_queue_t;

static void queue_init(bfs_queue_t* q)    { q->head = q->tail = 0; }
static int  queue_empty(bfs_queue_t* q)   { return q->head == q->tail; }
static void queue_push(bfs_queue_t* q, int v) { q->data[q->tail++] = v; }
static int  queue_pop(bfs_queue_t* q)     { return q->data[q->head++]; }

/* ═══════════════════════════════════════════════════════════════
 * Lifecycle
 * ═══════════════════════════════════════════════════════════════ */

ac_automaton_t* ac_create(void) {
    ac_automaton_t* ac = (ac_automaton_t*)calloc(1, sizeof(ac_automaton_t));
    if (!ac) return NULL;

    /* Initialize root node (index 0) */
    node_init(&ac->nodes[0]);
    ac->node_count    = 1;
    ac->pattern_count = 0;
    ac->compiled      = 0;

    return ac;
}

void ac_destroy(ac_automaton_t* ac) {
    if (!ac) return;
    for (int i = 0; i < ac->pattern_count; i++) {
        free(ac->patterns[i].text);
    }
    free(ac);
}

/* ═══════════════════════════════════════════════════════════════
 * Pattern loading
 * ═══════════════════════════════════════════════════════════════ */

int ac_add_pattern(ac_automaton_t* ac, const char* pattern, size_t len,
                   const char* category) {
    if (!ac || !pattern) return -1;
    if (ac->compiled) return -1;    /* Cannot add after compile */
    if (ac->pattern_count >= AC_MAX_PATTERNS) return -1;

    if (len == 0) len = strlen(pattern);
    if (len == 0) return -1;

    /* Store pattern */
    int pid = ac->pattern_count;
    ac->patterns[pid].text = (char*)malloc(len + 1);
    if (!ac->patterns[pid].text) return -1;

    /* Store lowercased copy */
    for (size_t i = 0; i < len; i++) {
        ac->patterns[pid].text[i] = to_lower(pattern[i]);
    }
    ac->patterns[pid].text[len] = '\0';
    ac->patterns[pid].len = len;

    if (category) {
        strncpy(ac->patterns[pid].category, category, AC_CATEGORY_LEN - 1);
        ac->patterns[pid].category[AC_CATEGORY_LEN - 1] = '\0';
    } else {
        ac->patterns[pid].category[0] = '\0';
    }

    /* Insert into trie */
    int cur = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)to_lower(pattern[i]);
        if (ac->nodes[cur].children[c] == -1) {
            if (ac->node_count >= AC_MAX_NODES) {
                free(ac->patterns[pid].text);
                return -1;
            }
            int next = ac->node_count++;
            node_init(&ac->nodes[next]);
            ac->nodes[next].depth = ac->nodes[cur].depth + 1;
            ac->nodes[cur].children[c] = next;
        }
        cur = ac->nodes[cur].children[c];
    }

    ac->nodes[cur].pattern_id = pid;
    ac->pattern_count++;

    return pid;
}

int ac_load_patterns_json(ac_automaton_t* ac, const char* path) {
    if (!ac || !path) return -1;

    /* Read file */
    FILE* fp = fopen(path, "rb");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char* json_str = (char*)malloc((size_t)fsize + 1);
    if (!json_str) { fclose(fp); return -1; }

    size_t read_n = fread(json_str, 1, (size_t)fsize, fp);
    json_str[read_n] = '\0';
    fclose(fp);

    /* Parse JSON */
    cJSON* root = cJSON_Parse(json_str);
    free(json_str);
    if (!root) return -1;

    cJSON* categories = cJSON_GetObjectItem(root, "categories");
    if (!categories) { cJSON_Delete(root); return -1; }

    int total_loaded = 0;

    /* Iterate categories */
    cJSON* cat = NULL;
    cJSON_ArrayForEach(cat, categories) {
        const char* cat_name = cat->string;
        cJSON* patterns_arr = cJSON_GetObjectItem(cat, "patterns");
        if (!cJSON_IsArray(patterns_arr)) continue;

        cJSON* pat = NULL;
        cJSON_ArrayForEach(pat, patterns_arr) {
            if (!cJSON_IsString(pat)) continue;
            int pid = ac_add_pattern(ac, pat->valuestring, 0, cat_name);
            if (pid >= 0) total_loaded++;
        }
    }

    cJSON_Delete(root);
    return total_loaded;
}

/* ═══════════════════════════════════════════════════════════════
 * Compilation (failure + output links via BFS)
 * ═══════════════════════════════════════════════════════════════ */

int ac_compile(ac_automaton_t* ac) {
    if (!ac) return -1;
    if (ac->compiled) return 0;

    bfs_queue_t q;
    queue_init(&q);

    /* Initialize: depth-1 nodes have failure → root */
    for (int c = 0; c < AC_ALPHABET_SIZE; c++) {
        int child = ac->nodes[0].children[c];
        if (child != -1) {
            ac->nodes[child].failure = 0;
            queue_push(&q, child);
        } else {
            /* Root loops back to itself for unmatched characters */
            ac->nodes[0].children[c] = 0;
        }
    }

    /* BFS to compute failure links */
    while (!queue_empty(&q)) {
        int u = queue_pop(&q);

        for (int c = 0; c < AC_ALPHABET_SIZE; c++) {
            int v = ac->nodes[u].children[c];
            if (v == -1) {
                /* Follow failure links for implicit transitions */
                ac->nodes[u].children[c] = ac->nodes[ac->nodes[u].failure].children[c];
            } else {
                /* Set failure link */
                ac->nodes[v].failure = ac->nodes[ac->nodes[u].failure].children[c];

                /* Set output link (dictionary suffix link) */
                if (ac->nodes[ac->nodes[v].failure].pattern_id >= 0) {
                    ac->nodes[v].output = ac->nodes[v].failure;
                } else {
                    ac->nodes[v].output = ac->nodes[ac->nodes[v].failure].output;
                }

                queue_push(&q, v);
            }
        }
    }

    ac->compiled = 1;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
 * Searching
 * ═══════════════════════════════════════════════════════════════ */

int ac_search(const ac_automaton_t* ac, const char* text, size_t len,
              ac_match_t* matches, int max_matches) {
    if (!ac || !ac->compiled || !text || !matches || max_matches <= 0)
        return 0;

    if (len == 0) len = strlen(text);

    int count = 0;
    int state = 0;

    for (size_t i = 0; i < len && count < max_matches; i++) {
        unsigned char c = (unsigned char)to_lower(text[i]);
        state = ac->nodes[state].children[c];

        /* Check for matches at current state */
        if (ac->nodes[state].pattern_id >= 0) {
            int pid = ac->nodes[state].pattern_id;
            matches[count].pattern_id   = (uint32_t)pid;
            matches[count].position     = (uint32_t)(i - ac->patterns[pid].len + 1);
            matches[count].pattern_text = ac->patterns[pid].text;
            strncpy(matches[count].category, ac->patterns[pid].category,
                    AC_CATEGORY_LEN);
            count++;
        }

        /* Check output links for overlapping shorter patterns */
        int out = ac->nodes[state].output;
        while (out != -1 && count < max_matches) {
            int pid = ac->nodes[out].pattern_id;
            matches[count].pattern_id   = (uint32_t)pid;
            matches[count].position     = (uint32_t)(i - ac->patterns[pid].len + 1);
            matches[count].pattern_text = ac->patterns[pid].text;
            strncpy(matches[count].category, ac->patterns[pid].category,
                    AC_CATEGORY_LEN);
            count++;
            out = ac->nodes[out].output;
        }
    }

    return count;
}

int ac_search_cb(const ac_automaton_t* ac, const char* text, size_t len,
                 ac_match_cb callback, void* user_data) {
    if (!ac || !ac->compiled || !text || !callback)
        return 0;

    if (len == 0) len = strlen(text);

    int count = 0;
    int state = 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)to_lower(text[i]);
        state = ac->nodes[state].children[c];

        if (ac->nodes[state].pattern_id >= 0) {
            int pid = ac->nodes[state].pattern_id;
            ac_match_t m;
            m.pattern_id   = (uint32_t)pid;
            m.position     = (uint32_t)(i - ac->patterns[pid].len + 1);
            m.pattern_text = ac->patterns[pid].text;
            strncpy(m.category, ac->patterns[pid].category, AC_CATEGORY_LEN);
            count++;
            if (callback(&m, user_data) != 0) return -count;
        }

        int out = ac->nodes[state].output;
        while (out != -1) {
            int pid = ac->nodes[out].pattern_id;
            ac_match_t m;
            m.pattern_id   = (uint32_t)pid;
            m.position     = (uint32_t)(i - ac->patterns[pid].len + 1);
            m.pattern_text = ac->patterns[pid].text;
            strncpy(m.category, ac->patterns[pid].category, AC_CATEGORY_LEN);
            count++;
            if (callback(&m, user_data) != 0) return -count;
            out = ac->nodes[out].output;
        }
    }

    return count;
}

int ac_pattern_count(const ac_automaton_t* ac) {
    return ac ? ac->pattern_count : 0;
}

const char* ac_pattern_category(const ac_automaton_t* ac, int pattern_id) {
    if (!ac || pattern_id < 0 || pattern_id >= ac->pattern_count) return "";
    return ac->patterns[pattern_id].category;
}
