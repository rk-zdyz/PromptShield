/*
 * PromptShield — REST API Server Routes
 * routes.c
 *
 * Endpoint handlers for the REST API:
 *   POST /api/v1/scan         — Scan text for injection
 *   POST /api/v1/scan/batch   — Batch scan
 *   POST /api/v1/canary/generate  — Generate canary token
 *   POST /api/v1/canary/check     — Check output for canary
 *   GET  /api/v1/stats        — Server statistics
 *   GET  /api/v1/health       — Health check
 *   GET  /api/v1/config       — Current config info
 *   GET  /                    — Serve dashboard
 */

#include "routes.h"
#include "cJSON.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════
 * Helpers
 * ═══════════════════════════════════════════════════════════════ */

static void send_cors_headers(struct mg_connection* conn, const char* origin) {
    if (origin && origin[0]) {
        mg_printf(conn, "Access-Control-Allow-Origin: %s\r\n", origin);
        mg_printf(conn, "Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS\r\n");
        mg_printf(conn, "Access-Control-Allow-Headers: Content-Type\r\n");
    }
}

static void send_json_response(struct mg_connection* conn, int status,
                                const char* cors_origin, cJSON* json) {
    char* body = cJSON_PrintUnformatted(json);
    size_t body_len = strlen(body);

    mg_printf(conn,
              "HTTP/1.1 %d %s\r\n"
              "Content-Type: application/json\r\n"
              "Content-Length: %zu\r\n",
              status,
              status == 200 ? "OK" : (status == 400 ? "Bad Request" : "Error"),
              body_len);
    send_cors_headers(conn, cors_origin);
    mg_printf(conn, "\r\n%s", body);

    free(body);
}

static char* read_request_body(struct mg_connection* conn, size_t* out_len) {
    const struct mg_request_info* ri = mg_get_request_info(conn);
    long long content_len = ri->content_length;
    if (content_len <= 0) content_len = 8192;  /* Default max */
    if (content_len > 10 * 1024 * 1024) content_len = 10 * 1024 * 1024;  /* 10MB max */

    char* buf = (char*)malloc((size_t)content_len + 1);
    if (!buf) return NULL;

    int n = mg_read(conn, buf, (size_t)content_len);
    if (n <= 0) { free(buf); return NULL; }

    buf[n] = '\0';
    if (out_len) *out_len = (size_t)n;
    return buf;
}

/** Build a standard scan result JSON */
static cJSON* result_to_json(const ps_result_t* r) {
    cJSON* root = cJSON_CreateObject();

    cJSON_AddStringToObject(root, "verdict", ps_verdict_str(r->verdict));
    cJSON_AddNumberToObject(root, "threat_score", (double)r->threat_score);
    cJSON_AddNumberToObject(root, "scan_time_us", r->scan_time_us);

    cJSON* layers = cJSON_AddArrayToObject(root, "layers");
    for (int i = 0; i < PS_LAYER_COUNT; i++) {
        cJSON* l = cJSON_CreateObject();
        cJSON_AddStringToObject(l, "name",
            r->layers[i].layer_name ? r->layers[i].layer_name : "");
        cJSON_AddStringToObject(l, "verdict", ps_verdict_str(r->layers[i].verdict));
        cJSON_AddNumberToObject(l, "confidence", (double)r->layers[i].confidence);
        cJSON_AddStringToObject(l, "details", r->layers[i].details);
        cJSON_AddItemToArray(layers, l);
    }

    if (r->match_count > 0) {
        cJSON* matches = cJSON_AddArrayToObject(root, "matches");
        for (uint32_t i = 0; i < r->match_count; i++) {
            cJSON* m = cJSON_CreateObject();
            cJSON_AddStringToObject(m, "pattern",
                r->matches[i].pattern ? r->matches[i].pattern : "");
            cJSON_AddStringToObject(m, "category",
                r->matches[i].category ? r->matches[i].category : "");
            cJSON_AddNumberToObject(m, "position", r->matches[i].position);
            cJSON_AddItemToArray(matches, m);
        }
    }

    return root;
}

/* ═══════════════════════════════════════════════════════════════
 * Handlers
 * ═══════════════════════════════════════════════════════════════ */

/* ── OPTIONS (CORS preflight) ─────────────────────────────── */
static int handle_options(struct mg_connection* conn, void* cbdata) {
    server_context_t* srv = (server_context_t*)cbdata;
    mg_printf(conn, "HTTP/1.1 204 No Content\r\n");
    send_cors_headers(conn, srv->cors_origin);
    mg_printf(conn, "\r\n");
    return 204;
}

/* ── POST /api/v1/scan ────────────────────────────────────── */
static int handle_scan(struct mg_connection* conn, void* cbdata) {
    server_context_t* srv = (server_context_t*)cbdata;

    const struct mg_request_info* ri = mg_get_request_info(conn);
    if (strcmp(ri->request_method, "OPTIONS") == 0)
        return handle_options(conn, cbdata);

    size_t body_len = 0;
    char* body = read_request_body(conn, &body_len);
    if (!body) {
        cJSON* err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Failed to read request body");
        send_json_response(conn, 400, srv->cors_origin, err);
        cJSON_Delete(err);
        return 400;
    }

    cJSON* req = cJSON_Parse(body);
    free(body);
    if (!req) {
        cJSON* err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Invalid JSON");
        send_json_response(conn, 400, srv->cors_origin, err);
        cJSON_Delete(err);
        return 400;
    }

    cJSON* text_item = cJSON_GetObjectItem(req, "text");
    if (!cJSON_IsString(text_item) || !text_item->valuestring[0]) {
        cJSON_Delete(req);
        cJSON* err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Missing 'text' field");
        send_json_response(conn, 400, srv->cors_origin, err);
        cJSON_Delete(err);
        return 400;
    }

    ps_result_t result = ps_scan_text(srv->ps_ctx, text_item->valuestring, 0);
    cJSON_Delete(req);

    cJSON* resp = result_to_json(&result);
    send_json_response(conn, 200, srv->cors_origin, resp);
    cJSON_Delete(resp);
    return 200;
}

/* ── POST /api/v1/scan/batch ──────────────────────────────── */
static int handle_scan_batch(struct mg_connection* conn, void* cbdata) {
    server_context_t* srv = (server_context_t*)cbdata;

    const struct mg_request_info* ri = mg_get_request_info(conn);
    if (strcmp(ri->request_method, "OPTIONS") == 0)
        return handle_options(conn, cbdata);

    size_t body_len = 0;
    char* body = read_request_body(conn, &body_len);
    if (!body) {
        cJSON* err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Failed to read request body");
        send_json_response(conn, 400, srv->cors_origin, err);
        cJSON_Delete(err);
        return 400;
    }

    cJSON* req = cJSON_Parse(body);
    free(body);
    if (!req) {
        cJSON* err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Invalid JSON");
        send_json_response(conn, 400, srv->cors_origin, err);
        cJSON_Delete(err);
        return 400;
    }

    cJSON* texts = cJSON_GetObjectItem(req, "texts");
    if (!cJSON_IsArray(texts)) {
        cJSON_Delete(req);
        cJSON* err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Missing 'texts' array");
        send_json_response(conn, 400, srv->cors_origin, err);
        cJSON_Delete(err);
        return 400;
    }

    cJSON* results = cJSON_CreateArray();
    cJSON* item = NULL;
    cJSON_ArrayForEach(item, texts) {
        if (!cJSON_IsString(item)) continue;
        ps_result_t r = ps_scan_text(srv->ps_ctx, item->valuestring, 0);
        cJSON_AddItemToArray(results, result_to_json(&r));
    }

    cJSON_Delete(req);

    cJSON* resp = cJSON_CreateObject();
    cJSON_AddItemToObject(resp, "results", results);
    send_json_response(conn, 200, srv->cors_origin, resp);
    cJSON_Delete(resp);
    return 200;
}

/* ── POST /api/v1/canary/generate ─────────────────────────── */
static int handle_canary_generate(struct mg_connection* conn, void* cbdata) {
    server_context_t* srv = (server_context_t*)cbdata;

    const struct mg_request_info* ri = mg_get_request_info(conn);
    if (strcmp(ri->request_method, "OPTIONS") == 0)
        return handle_options(conn, cbdata);

    char canary[64];
    int len = ps_canary_generate(srv->ps_ctx, canary, sizeof(canary));
    if (len <= 0) {
        cJSON* err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Failed to generate canary");
        send_json_response(conn, 500, srv->cors_origin, err);
        cJSON_Delete(err);
        return 500;
    }

    /* Also register it */
    ps_canary_register(srv->ps_ctx, canary);

    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "canary", canary);
    cJSON_AddStringToObject(resp, "status", "registered");
    send_json_response(conn, 200, srv->cors_origin, resp);
    cJSON_Delete(resp);
    return 200;
}

/* ── POST /api/v1/canary/check ────────────────────────────── */
static int handle_canary_check(struct mg_connection* conn, void* cbdata) {
    server_context_t* srv = (server_context_t*)cbdata;

    const struct mg_request_info* ri = mg_get_request_info(conn);
    if (strcmp(ri->request_method, "OPTIONS") == 0)
        return handle_options(conn, cbdata);

    size_t body_len = 0;
    char* body = read_request_body(conn, &body_len);
    if (!body) {
        cJSON* err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Failed to read request body");
        send_json_response(conn, 400, srv->cors_origin, err);
        cJSON_Delete(err);
        return 400;
    }

    cJSON* req = cJSON_Parse(body);
    free(body);

    cJSON* output = cJSON_GetObjectItem(req, "output");
    if (!cJSON_IsString(output)) {
        cJSON_Delete(req);
        cJSON* err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Missing 'output' field");
        send_json_response(conn, 400, srv->cors_origin, err);
        cJSON_Delete(err);
        return 400;
    }

    ps_result_t result = ps_scan_output(srv->ps_ctx, output->valuestring, 0);
    cJSON_Delete(req);

    cJSON* resp = result_to_json(&result);
    send_json_response(conn, 200, srv->cors_origin, resp);
    cJSON_Delete(resp);
    return 200;
}

/* ── GET /api/v1/stats ────────────────────────────────────── */
static int handle_stats(struct mg_connection* conn, void* cbdata) {
    server_context_t* srv = (server_context_t*)cbdata;

    const struct mg_request_info* ri = mg_get_request_info(conn);
    if (strcmp(ri->request_method, "OPTIONS") == 0)
        return handle_options(conn, cbdata);

    ps_stats_t stats = ps_get_stats(srv->ps_ctx);

    cJSON* resp = cJSON_CreateObject();
    cJSON_AddNumberToObject(resp, "total_scans", (double)stats.total_scans);
    cJSON_AddNumberToObject(resp, "safe_count", (double)stats.verdicts[0]);
    cJSON_AddNumberToObject(resp, "suspicious_count", (double)stats.verdicts[1]);
    cJSON_AddNumberToObject(resp, "malicious_count", (double)stats.verdicts[2]);
    cJSON_AddNumberToObject(resp, "avg_scan_time_us", stats.avg_scan_time_us);
    cJSON_AddNumberToObject(resp, "total_scan_time_us", stats.total_scan_time_us);
    cJSON_AddStringToObject(resp, "version", ps_version());

    send_json_response(conn, 200, srv->cors_origin, resp);
    cJSON_Delete(resp);
    return 200;
}

/* ── GET /api/v1/health ───────────────────────────────────── */
static int handle_health(struct mg_connection* conn, void* cbdata) {
    server_context_t* srv = (server_context_t*)cbdata;

    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "healthy");
    cJSON_AddStringToObject(resp, "version", ps_version());

    send_json_response(conn, 200, srv->cors_origin, resp);
    cJSON_Delete(resp);
    return 200;
}

/* ── POST /api/v1/session/reset ───────────────────────────── */
static int handle_session_reset(struct mg_connection* conn, void* cbdata) {
    server_context_t* srv = (server_context_t*)cbdata;
    const struct mg_request_info* ri = mg_get_request_info(conn);
    if (strcmp(ri->request_method, "OPTIONS") == 0)
        return handle_options(conn, cbdata);

    ps_session_reset(srv->ps_ctx);

    cJSON* resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", 1);
    cJSON_AddStringToObject(resp, "message", "Session context reset");
    send_json_response(conn, 200, srv->cors_origin, resp);
    cJSON_Delete(resp);
    return 200;
}

/* ═══════════════════════════════════════════════════════════════
 * Embedded Dashboard (inline HTML/CSS/JS)
 * ═══════════════════════════════════════════════════════════════ */

/* Forward declaration — the dashboard HTML is defined in dashboard_html.h */
extern const char* DASHBOARD_HTML;
extern const unsigned int DASHBOARD_HTML_LEN;

/* ── GET / (Dashboard) ────────────────────────────────────── */
static int handle_dashboard(struct mg_connection* conn, void* cbdata) {
    server_context_t* srv = (server_context_t*)cbdata;

    if (!srv->dashboard_enabled) {
        mg_printf(conn, "HTTP/1.1 404 Not Found\r\n\r\n");
        return 404;
    }

    if (DASHBOARD_HTML && DASHBOARD_HTML_LEN > 0) {
        mg_printf(conn,
                  "HTTP/1.1 200 OK\r\n"
                  "Content-Type: text/html; charset=utf-8\r\n"
                  "Content-Length: %u\r\n"
                  "Cache-Control: no-cache\r\n"
                  "\r\n",
                  DASHBOARD_HTML_LEN);
        mg_write(conn, DASHBOARD_HTML, DASHBOARD_HTML_LEN);
    } else {
        const char* fallback = "<html><body><h1>PromptShield Dashboard</h1>"
                                "<p>Dashboard not embedded in this build.</p></body></html>";
        mg_printf(conn,
                  "HTTP/1.1 200 OK\r\n"
                  "Content-Type: text/html\r\n"
                  "Content-Length: %zu\r\n\r\n%s",
                  strlen(fallback), fallback);
    }
    return 200;
}

/* ═══════════════════════════════════════════════════════════════
 * Route Registration
 * ═══════════════════════════════════════════════════════════════ */

void routes_register(struct mg_context* mg_ctx, server_context_t* srv_ctx) {
    mg_set_request_handler(mg_ctx, "/api/v1/scan$",            handle_scan,            srv_ctx);
    mg_set_request_handler(mg_ctx, "/api/v1/scan/batch$",      handle_scan_batch,      srv_ctx);
    mg_set_request_handler(mg_ctx, "/api/v1/canary/generate$", handle_canary_generate, srv_ctx);
    mg_set_request_handler(mg_ctx, "/api/v1/canary/check$",    handle_canary_check,    srv_ctx);
    mg_set_request_handler(mg_ctx, "/api/v1/stats$",           handle_stats,           srv_ctx);
    mg_set_request_handler(mg_ctx, "/api/v1/health$",          handle_health,          srv_ctx);
    mg_set_request_handler(mg_ctx, "/api/v1/session/reset$",   handle_session_reset,   srv_ctx);
    mg_set_request_handler(mg_ctx, "/$",                       handle_dashboard,       srv_ctx);
}
