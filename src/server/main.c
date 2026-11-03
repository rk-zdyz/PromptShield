/*
 * PromptShield — REST API Server
 * main.c
 *
 * Starts a Civetweb HTTP server with the PromptShield API endpoints
 * and embedded web dashboard.
 */

#include "civetweb.h"
#include "routes.h"
#include "promptshield/promptshield.h"

/* Include the pipeline header to access config */
#include "config.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifdef _WIN32
#include <windows.h>
#define sleep(s) Sleep((s)*1000)
#else
#include <unistd.h>
#endif

/* Global stop flag */
static volatile int g_running = 1;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* ═══════════════════════════════════════════════════════════════
 * Main
 * ═══════════════════════════════════════════════════════════════ */

int main(int argc, char** argv) {
    const char* config_path = "data/config.json";

    /* Parse args */
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) &&
            i + 1 < argc) {
            config_path = argv[++i];
        }
        if (strcmp(argv[i], "--version") == 0) {
            printf("PromptShield Server v%s\n", ps_version());
            return 0;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: promptshield-server [OPTIONS]\n");
            printf("  -c, --config <path>   Config file (default: data/config.json)\n");
            printf("  --version             Show version\n");
            printf("  -h, --help            Show this help\n");
            return 0;
        }
    }

    /* Initialize PromptShield */
    printf("\n");
    printf("  \xe2\x96\x88\xe2\x96\x88\xe2\x96\x88 PromptShield Server v%s \xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\n", ps_version());
    printf("  Prompt Injection Firewall — REST API\n\n");

    ps_context_t* ps_ctx = ps_create(config_path);
    if (!ps_ctx) {
        fprintf(stderr, "Error: Failed to initialize PromptShield\n");
        return 1;
    }

    /* Load config for server settings */
    ps_config_t cfg = ps_config_load(config_path);

    /* Build Civetweb options */
    char port_str[32];
    char threads_str[16];
    snprintf(port_str, sizeof(port_str), "%d", cfg.server_port);
    snprintf(threads_str, sizeof(threads_str), "%d", cfg.server_threads);

    const char* options[] = {
        "listening_ports",       port_str,
        "num_threads",           threads_str,
        "request_timeout_ms",    "5000",
        "enable_keep_alive",     "yes",
        "access_log_file",       "",
        "error_log_file",        "",
        NULL
    };

    /* Initialize Civetweb */
    mg_init_library(0);

    struct mg_context* mg_ctx = mg_start(NULL, NULL, options);
    if (!mg_ctx) {
        fprintf(stderr, "Error: Failed to start HTTP server on port %s\n", port_str);
        ps_destroy(ps_ctx);
        return 1;
    }

    /* Setup server context */
    server_context_t srv_ctx;
    srv_ctx.ps_ctx             = ps_ctx;
    srv_ctx.cors_origin        = cfg.server_cors;
    srv_ctx.dashboard_enabled  = cfg.server_dashboard;

    /* Register routes */
    routes_register(mg_ctx, &srv_ctx);

    printf("  Listening on http://%s:%s\n", cfg.server_host, port_str);
    printf("  Dashboard:   http://%s:%s/\n", cfg.server_host, port_str);
    printf("  API:         http://%s:%s/api/v1/\n\n", cfg.server_host, port_str);
    printf("  Press Ctrl+C to stop.\n\n");

    /* Signal handling */
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    /* Run until stopped */
    while (g_running) {
        sleep(1);
    }

    printf("\n  Shutting down...\n");

    mg_stop(mg_ctx);
    mg_exit_library();
    ps_destroy(ps_ctx);

    printf("  Done.\n");
    return 0;
}
