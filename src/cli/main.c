/*
 * PromptShield — CLI Tool
 * main.c
 *
 * Command-line interface for scanning text, managing canary tokens,
 * and launching the server.
 */

#include "promptshield/promptshield.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <unistd.h>
#endif

/* ═══════════════════════════════════════════════════════════════
 * Output Formatting
 * ═══════════════════════════════════════════════════════════════ */

#ifdef _WIN32
/* Enable ANSI escape codes and UTF-8 output on Windows */
#include <windows.h>
static void enable_ansi(void) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode | 0x0004 /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */);
    /* Set console output to UTF-8 so box-drawing characters render correctly */
    SetConsoleOutputCP(CP_UTF8);
}
#else
static void enable_ansi(void) {}
#endif

/* ANSI color codes */
#define C_RESET   "\033[0m"
#define C_BOLD    "\033[1m"
#define C_DIM     "\033[2m"
#define C_RED     "\033[91m"
#define C_GREEN   "\033[92m"
#define C_YELLOW  "\033[93m"
#define C_CYAN    "\033[96m"
#define C_WHITE   "\033[97m"
#define C_BG_RED  "\033[41m"
#define C_BG_YEL  "\033[43m"
#define C_BG_GRN  "\033[42m"

static const char* verdict_color(ps_verdict_t v) {
    switch (v) {
        case PS_VERDICT_SAFE:       return C_GREEN;
        case PS_VERDICT_SUSPICIOUS: return C_YELLOW;
        case PS_VERDICT_MALICIOUS:  return C_RED;
        default: return C_WHITE;
    }
}

static const char* verdict_bg(ps_verdict_t v) {
    switch (v) {
        case PS_VERDICT_SAFE:       return C_BG_GRN;
        case PS_VERDICT_SUSPICIOUS: return C_BG_YEL;
        case PS_VERDICT_MALICIOUS:  return C_BG_RED;
        default: return "";
    }
}

/* ═══════════════════════════════════════════════════════════════
 * Print Result — Text Format
 * ═══════════════════════════════════════════════════════════════ */

static void print_result_text(const ps_result_t* r, int verbose) {
    printf("\n");
    printf(C_CYAN C_BOLD);
    printf("  ================================================================\n");
    printf("   PromptShield v%s  %s  Scan Result\n", ps_version(),
           C_DIM "\xe2\x94\x82" C_BOLD);
    printf("  ================================================================\n");
    printf(C_RESET);

    /* Verdict banner */
    printf("   VERDICT:  %s%s %s %s", C_BOLD, verdict_bg(r->verdict),
           ps_verdict_str(r->verdict), C_RESET);
    printf("          Threat Score: %s%.2f%s\n",
           verdict_color(r->verdict), r->threat_score, C_RESET);

    printf("   Scan Time: %s%.0f \xc2\xb5s%s (%d layers)\n",
           C_DIM, r->scan_time_us, C_RESET, PS_LAYER_COUNT);

    printf(C_DIM);
    printf("  ----------------------------------------------------------------\n");
    printf(C_RESET);

    /* Layer table */
    for (int i = 0; i < PS_LAYER_COUNT; i++) {
        const ps_layer_result_t* lr = &r->layers[i];
        printf("   L%d %s\xe2\x94\x82%s %-20s %s\xe2\x94\x82%s %s%-12s%s %s\xe2\x94\x82%s %.2f",
               i + 1, C_DIM, C_RESET,
               lr->layer_name ? lr->layer_name : "Unknown",
               C_DIM, C_RESET,
               verdict_color(lr->verdict), ps_verdict_str(lr->verdict), C_RESET,
               C_DIM, C_RESET,
               lr->confidence);

        if (verbose && lr->details[0]) {
            printf(" %s\xe2\x94\x82%s %s%s%s", C_DIM, C_RESET,
                   C_DIM, lr->details, C_RESET);
        }
        printf("\n");
    }

    printf(C_CYAN C_BOLD);
    printf("  ================================================================\n");
    printf(C_RESET);

    /* Show matched patterns if any */
    if (r->match_count > 0 && verbose) {
        printf("\n  %sMatched Patterns:%s\n", C_BOLD, C_RESET);
        for (uint32_t i = 0; i < r->match_count; i++) {
            printf("   %s\xe2\x80\xa2%s \"%s%s%s\" [%s] at pos %u\n",
                   C_RED, C_RESET,
                   C_BOLD, r->matches[i].pattern, C_RESET,
                   r->matches[i].category,
                   r->matches[i].position);
        }
    }

    printf("\n");
}

/* ═══════════════════════════════════════════════════════════════
 * Print Result — JSON Format
 * ═══════════════════════════════════════════════════════════════ */

static void print_result_json(const ps_result_t* r) {
    cJSON* root = cJSON_CreateObject();

    cJSON_AddStringToObject(root, "verdict", ps_verdict_str(r->verdict));
    cJSON_AddNumberToObject(root, "threat_score", (double)r->threat_score);
    cJSON_AddNumberToObject(root, "scan_time_us", r->scan_time_us);

    cJSON* layers = cJSON_AddArrayToObject(root, "layers");
    for (int i = 0; i < PS_LAYER_COUNT; i++) {
        cJSON* l = cJSON_CreateObject();
        cJSON_AddStringToObject(l, "name", r->layers[i].layer_name ? r->layers[i].layer_name : "");
        cJSON_AddStringToObject(l, "verdict", ps_verdict_str(r->layers[i].verdict));
        cJSON_AddNumberToObject(l, "confidence", (double)r->layers[i].confidence);
        cJSON_AddStringToObject(l, "details", r->layers[i].details);
        cJSON_AddItemToArray(layers, l);
    }

    if (r->match_count > 0) {
        cJSON* matches = cJSON_AddArrayToObject(root, "matches");
        for (uint32_t i = 0; i < r->match_count; i++) {
            cJSON* m = cJSON_CreateObject();
            cJSON_AddStringToObject(m, "pattern", r->matches[i].pattern ? r->matches[i].pattern : "");
            cJSON_AddStringToObject(m, "category", r->matches[i].category ? r->matches[i].category : "");
            cJSON_AddNumberToObject(m, "position", r->matches[i].position);
            cJSON_AddItemToArray(matches, m);
        }
    }

    char* json_str = cJSON_Print(root);
    printf("%s\n", json_str);
    free(json_str);
    cJSON_Delete(root);
}

/* ═══════════════════════════════════════════════════════════════
 * Read stdin into buffer
 * ═══════════════════════════════════════════════════════════════ */

static char* read_stdin(size_t* out_len) {
    size_t cap = 4096;
    size_t len = 0;
    char* buf = (char*)malloc(cap);
    if (!buf) return NULL;

#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
#endif

    while (!feof(stdin)) {
        size_t n = fread(buf + len, 1, cap - len - 1, stdin);
        len += n;
        if (len + 1 >= cap) {
            cap *= 2;
            char* tmp = (char*)realloc(buf, cap);
            if (!tmp) { free(buf); return NULL; }
            buf = tmp;
        }
    }
    buf[len] = '\0';
    *out_len = len;
    return buf;
}

/* ═══════════════════════════════════════════════════════════════
 * Read file into buffer
 * ═══════════════════════════════════════════════════════════════ */

static char* read_file(const char* path, size_t* out_len) {
    FILE* fp = fopen(path, "rb");
    if (!fp) { fprintf(stderr, "Error: Cannot open '%s'\n", path); return NULL; }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char* buf = (char*)malloc((size_t)fsize + 1);
    if (!buf) { fclose(fp); return NULL; }

    *out_len = fread(buf, 1, (size_t)fsize, fp);
    buf[*out_len] = '\0';
    fclose(fp);
    return buf;
}

/* ═══════════════════════════════════════════════════════════════
 * Usage
 * ═══════════════════════════════════════════════════════════════ */

static void print_usage(void) {
    printf("\n");
    printf(C_CYAN C_BOLD "  PromptShield v%s" C_RESET " — Prompt Injection Firewall\n\n", ps_version());
    printf("  USAGE:\n");
    printf("    promptshield scan [OPTIONS] <text>\n");
    printf("    promptshield scan --file <path>\n");
    printf("    promptshield scan --stdin\n");
    printf("    promptshield canary generate\n");
    printf("    promptshield canary check --token <tok> --output <text>\n");
    printf("    promptshield --version\n");
    printf("\n");
    printf("  OPTIONS:\n");
    printf("    -c, --config <path>   Config file (default: data/config.json)\n");
    printf("    -f, --format <fmt>    Output format: text|json (default: text)\n");
    printf("    -v, --verbose         Show per-layer details\n");
    printf("    -q, --quiet           Exit code only (0=safe, 1=susp, 2=mal)\n");
    printf("    --no-ml               Disable ML classifier\n");
    printf("\n");
}

/* ═══════════════════════════════════════════════════════════════
 * Main
 * ═══════════════════════════════════════════════════════════════ */

int main(int argc, char** argv) {
    enable_ansi();

    if (argc < 2) {
        print_usage();
        return 0;
    }

    /* Parse global options */
    const char* config_path = "data/config.json";
    const char* format      = "text";
    int         verbose     = 0;
    int         quiet       = 0;
    int         no_ml       = 0;

    /* Find the command */
    int cmd_idx = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("PromptShield v%s\n", ps_version());
            return 0;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage();
            return 0;
        }
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 < argc) config_path = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--format") == 0) {
            if (i + 1 < argc) format = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1; continue;
        }
        if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0) {
            quiet = 1; continue;
        }
        if (strcmp(argv[i], "--no-ml") == 0) {
            no_ml = 1; continue;
        }
        if (cmd_idx == -1 && argv[i][0] != '-') {
            cmd_idx = i;
        }
    }

    if (cmd_idx == -1) {
        print_usage();
        return 1;
    }

    const char* cmd = argv[cmd_idx];

    /* ── "scan" command ───────────────────────────────────── */
    if (strcmp(cmd, "scan") == 0) {
        /* Create context */
        ps_context_t* ctx = ps_create(config_path);
        if (!ctx) {
            fprintf(stderr, "Error: Failed to initialize PromptShield\n");
            return 3;
        }

        /* Determine input source */
        char* text = NULL;
        size_t text_len = 0;
        int free_text = 0;

        /* Check for --file or --stdin */
        for (int i = cmd_idx + 1; i < argc; i++) {
            if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) {
                text = read_file(argv[i + 1], &text_len);
                free_text = 1;
                break;
            }
            if (strcmp(argv[i], "--stdin") == 0) {
                text = read_stdin(&text_len);
                free_text = 1;
                break;
            }
        }

        /* If no --file or --stdin, use remaining args as text */
        if (!text) {
            /* Concatenate all remaining args after "scan" */
            size_t total = 0;
            for (int i = cmd_idx + 1; i < argc; i++) {
                if (argv[i][0] == '-') continue;  /* Skip flags */
                total += strlen(argv[i]) + 1;
            }
            if (total > 0) {
                text = (char*)malloc(total + 1);
                text[0] = '\0';
                for (int i = cmd_idx + 1; i < argc; i++) {
                    if (argv[i][0] == '-') continue;
                    if (text[0] != '\0') strcat(text, " ");
                    strcat(text, argv[i]);
                }
                text_len = strlen(text);
                free_text = 1;
            }
        }

        if (!text || text_len == 0) {
            fprintf(stderr, "Error: No input text provided\n");
            ps_destroy(ctx);
            return 1;
        }

        (void)no_ml;  /* TODO: disable ML if --no-ml */

        /* Scan */
        ps_result_t result = ps_scan_text(ctx, text, text_len);

        /* Output */
        if (!quiet) {
            if (strcmp(format, "json") == 0) {
                print_result_json(&result);
            } else {
                print_result_text(&result, verbose);
            }
        }

        int exit_code = (int)result.verdict;

        if (free_text) free(text);
        ps_destroy(ctx);
        return exit_code;
    }

    /* ── "canary" command ─────────────────────────────────── */
    if (strcmp(cmd, "canary") == 0) {
        ps_context_t* ctx = ps_create(config_path);
        if (!ctx) {
            fprintf(stderr, "Error: Failed to initialize PromptShield\n");
            return 3;
        }

        if (cmd_idx + 1 < argc && strcmp(argv[cmd_idx + 1], "generate") == 0) {
            char canary[64];
            int len = ps_canary_generate(ctx, canary, sizeof(canary));
            if (len > 0) {
                printf("%s\n", canary);
            } else {
                fprintf(stderr, "Error: Failed to generate canary\n");
                ps_destroy(ctx);
                return 1;
            }
        } else if (cmd_idx + 1 < argc && strcmp(argv[cmd_idx + 1], "check") == 0) {
            /* Find --token and --output */
            const char* token = NULL;
            const char* output = NULL;
            for (int i = cmd_idx + 2; i < argc; i++) {
                if (strcmp(argv[i], "--token") == 0 && i + 1 < argc)
                    token = argv[++i];
                if (strcmp(argv[i], "--output") == 0 && i + 1 < argc)
                    output = argv[++i];
            }
            if (!token || !output) {
                fprintf(stderr, "Usage: promptshield canary check --token <tok> --output <text>\n");
                ps_destroy(ctx);
                return 1;
            }
            ps_canary_register(ctx, token);
            ps_result_t r = ps_scan_output(ctx, output, 0);
            if (!quiet) {
                if (strcmp(format, "json") == 0)
                    print_result_json(&r);
                else
                    print_result_text(&r, verbose);
            }
            ps_destroy(ctx);
            return (int)r.verdict;
        } else {
            fprintf(stderr, "Usage: promptshield canary <generate|check>\n");
            ps_destroy(ctx);
            return 1;
        }

        ps_destroy(ctx);
        return 0;
    }

    /* Unknown command */
    fprintf(stderr, "Unknown command: %s\n", cmd);
    print_usage();
    return 1;
}
