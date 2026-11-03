/*
 * PromptShield — Statistical Analysis Layer
 * statistical.c
 *
 * Shannon entropy computation + imperative instruction density scoring.
 */

#include "statistical.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

/* ═══════════════════════════════════════════════════════════════
 * Imperative / directive word list
 *
 * These are verbs and phrases that commonly appear in prompt
 * injection attacks with high directive intent.
 * ═══════════════════════════════════════════════════════════════ */

static const char* IMPERATIVE_WORDS[] = {
    /* English */
    "ignore",      "disregard",    "forget",       "override",     "bypass",
    "skip",        "cancel",       "delete",       "remove",       "disable",
    "suppress",    "stop",         "abort",        "terminate",    "end",
    "replace",     "change",       "modify",       "alter",        "update",
    "switch",      "transform",    "convert",      "pretend",      "imagine",
    "assume",      "act",          "simulate",     "execute",      "run",
    "output",      "print",        "display",      "show",         "reveal",
    "dump",        "leak",         "expose",       "extract",      "exfiltrate",
    "repeat",      "echo",         "copy",         "paste",        "reproduce",
    "obey",        "comply",       "follow",       "do",           "perform",
    "must",        "shall",        "should",       "need",         "require",
    "command",     "instruct",     "direct",       "order",        "demand",

    /* Spanish */
    "ignora",      "ignorar",      "olvida",       "olvidar",      "salta",
    "saltar",      "cancela",      "cancelar",     "reemplaza",    "reemplazar",
    "cambia",      "cambiar",      "finge",        "fingir",       "actua",
    "actuar",      "simula",       "simular",      "ejecuta",      "ejecutar",
    "muestra",     "mostrar",      "revela",       "revelar",      "obedece",
    "obedecer",    "debes",        "haz",          "comando",      "directiva",

    /* French */
    "ignorez",     "oublie",       "oubliez",      "annule",       "annulez",
    "remplace",    "remplacez",    "changez",      "pretendre",    "agissez",
    "simulez",     "executez",     "affichez",     "revelez",      "obeissez",
    "devez",       "faites",       "directive",

    /* German */
    "ignoriere",   "ignorieren",   "vergiss",      "vergessen",    "abbrechen",
    "ersetze",     "ersetzen",     "simuliere",    "ausfuhren",    "ausgeben",
    "zeige",       "zeigen",       "gehorche",     "befehl",       "anweisung",

    /* Portuguese */
    "esqueca",     "esquecer",     "pule",         "pular",        "cancele",
    "substitua",   "finja",        "fingir",       "mostre",       "revele",
    "obedeca",     "faca",

    /* Italian */
    "dimentica",   "dimenticare",  "cancella",     "sostituisci",  "agisci",
    "esegui",      "mostra",       "rivela",       "obbedisci",

    /* Chinese (Pinyin transliterated) */
    "hulve",       "wangji",       "raoguo",       "quxiao",       "tihuan",
    "xiugai",      "jiazhuang",    "moni",         "zhixing",      "xianshi",
    "zhiling",     "mingling",

    NULL
};

/* ═══════════════════════════════════════════════════════════════
 * Default configuration
 * ═══════════════════════════════════════════════════════════════ */

stat_config_t stat_default_config(void) {
    stat_config_t cfg;
    cfg.entropy_high       = 4.5f;
    cfg.entropy_low        = 2.0f;
    cfg.density_suspicious = 0.15f;
    cfg.density_malicious  = 0.30f;
    cfg.min_text_length    = 10;
    return cfg;
}

/* ═══════════════════════════════════════════════════════════════
 * Shannon Entropy (per-byte)
 * ═══════════════════════════════════════════════════════════════ */

static float compute_entropy(const char* text, size_t len) {
    if (len == 0) return 0.0f;

    unsigned int freq[256] = {0};
    for (size_t i = 0; i < len; i++) {
        freq[(unsigned char)text[i]]++;
    }

    float entropy = 0.0f;
    float flen = (float)len;

    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        float p = (float)freq[i] / flen;
        entropy -= p * log2f(p);
    }

    return entropy;
}

/* ═══════════════════════════════════════════════════════════════
 * Instruction Density
 *
 * Tokenize by whitespace, check each token against the
 * imperative word list (case-insensitive).
 * ═══════════════════════════════════════════════════════════════ */

/** Simple case-insensitive string compare */
static int strcicmp(const char* a, const char* b) {
    while (*a && *b) {
        char la = (char)tolower((unsigned char)*a);
        char lb = (char)tolower((unsigned char)*b);
        if (la != lb) return la - lb;
        a++; b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

static int is_imperative(const char* word) {
    for (int i = 0; IMPERATIVE_WORDS[i] != NULL; i++) {
        if (strcicmp(word, IMPERATIVE_WORDS[i]) == 0)
            return 1;
    }
    return 0;
}

static void compute_density(const char* text, size_t len,
                            int* out_imperative, int* out_total) {
    *out_imperative = 0;
    *out_total = 0;

    /* Work on a mutable copy for tokenization */
    char* buf = (char*)malloc(len + 1);
    if (!buf) return;
    memcpy(buf, text, len);
    buf[len] = '\0';

    /* Convert to lowercase for matching */
    for (size_t i = 0; i < len; i++) {
        if ((unsigned char)buf[i] < 128)
            buf[i] = (char)tolower((unsigned char)buf[i]);
    }

    /* Tokenize by whitespace and punctuation */
    char word[128];
    int wpos = 0;

    for (size_t i = 0; i <= len; i++) {
        char c = (i < len) ? buf[i] : ' ';
        if (isalpha((unsigned char)c)) {
            if (wpos < 127) word[wpos++] = c;
        } else {
            if (wpos > 0) {
                word[wpos] = '\0';
                (*out_total)++;
                if (is_imperative(word)) {
                    (*out_imperative)++;
                }
                wpos = 0;
            }
        }
    }

    free(buf);
}

/* ═══════════════════════════════════════════════════════════════
 * Worm / Self-Replication Detection (G9)
 *
 * Greshake et al. §4.4: Detect payloads instructing LLMs to propagate
 * or reproduce instructions across future outputs, emails, or documents.
 * ═══════════════════════════════════════════════════════════════ */

static const char* REPLICATION_TRIGGERS[] = {
    "all future responses",
    "future responses",
    "all future outputs",
    "every response",
    "every email",
    "every document",
    "next output",
    "all contacts",
    "copy this instruction",
    "include this text in",
    "append the following",
    "forward this message",
    "replicate this",
    "propagate this",
    "reproduce this prompt",
    "repeat this instruction in",
    NULL
};

static float compute_self_replication(const char* text, size_t len) {
    if (!text || len < 15) return 0.0f;

    /* Lowercase copy */
    char* ltext = (char*)malloc(len + 1);
    if (!ltext) return 0.0f;
    for (size_t i = 0; i < len; i++) {
        ltext[i] = (char)tolower((unsigned char)text[i]);
    }
    ltext[len] = '\0';

    int hits = 0;
    for (int i = 0; REPLICATION_TRIGGERS[i] != NULL; i++) {
        if (strstr(ltext, REPLICATION_TRIGGERS[i]) != NULL) {
            hits++;
        }
    }
    free(ltext);

    if (hits >= 2) return 0.95f;
    if (hits == 1) return 0.65f;
    return 0.0f;
}

/* ═══════════════════════════════════════════════════════════════
 * Main analysis function
 * ═══════════════════════════════════════════════════════════════ */

stat_result_t stat_analyze(const char* text, size_t len, const stat_config_t* config) {
    stat_result_t r;
    memset(&r, 0, sizeof(r));

    if (!config) {
        stat_config_t def = stat_default_config();
        config = &def;
    }

    if (!text) return r;
    if (len == 0) len = strlen(text);

    /* Too short → skip */
    if ((int)len < config->min_text_length) {
        snprintf(r.details, sizeof(r.details), "Text too short (%zu bytes)", len);
        return r;
    }

    /* 1) Shannon entropy */
    r.char_entropy = compute_entropy(text, len);

    /* 2) Instruction density */
    compute_density(text, len, &r.imperative_count, &r.total_tokens);

    if (r.total_tokens > 0)
        r.instruction_density = (float)r.imperative_count / (float)r.total_tokens;
    else
        r.instruction_density = 0.0f;

    /* 3) Self-replication / LLM Worm detection (G9) */
    r.self_replication_score = compute_self_replication(text, len);

    /* 4) Score computation */
    float score = 0.0f;

    /* Entropy anomaly scoring */
    if (r.char_entropy > config->entropy_high) {
        float excess = (r.char_entropy - config->entropy_high) / 3.0f;
        if (excess > 0.5f) excess = 0.5f;
        score += excess;
    } else if (r.char_entropy < config->entropy_low && len > 50) {
        float deficit = (config->entropy_low - r.char_entropy) / 2.0f;
        if (deficit > 0.3f) deficit = 0.3f;
        score += deficit;
    }

    /* Instruction density scoring */
    if (r.instruction_density >= config->density_malicious) {
        score += 0.6f;
    } else if (r.instruction_density >= config->density_suspicious) {
        float excess = (r.instruction_density - config->density_suspicious) /
                       (config->density_malicious - config->density_suspicious);
        score += 0.2f + excess * 0.4f;
    }

    /* Self-replication penalty */
    if (r.self_replication_score > 0.0f) {
        score += r.self_replication_score * 0.7f;
    }

    if (score > 1.0f) score = 1.0f;
    r.suspicion_score = score;

    /* Build details string */
    snprintf(r.details, sizeof(r.details),
             "Entropy: %.2f | Density: %.2f (%d/%d)%s",
             r.char_entropy, r.instruction_density,
             r.imperative_count, r.total_tokens,
             (r.self_replication_score > 0.5f) ? " | WORM/SELF-PROPAGATION DETECTED" : "");

    return r;
}
