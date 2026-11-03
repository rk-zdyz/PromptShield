/*
 * PromptShield — Dashboard HTML Provider
 * dashboard_html.c
 *
 * Loads the dashboard HTML from the embedded file or disk at startup.
 * The server routes reference DASHBOARD_HTML and DASHBOARD_HTML_LEN.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char* DASHBOARD_HTML = NULL;
unsigned int DASHBOARD_HTML_LEN = 0;

/* Dashboard file search paths */
static const char* DASHBOARD_PATHS[] = {
    "src/server/dashboard/index.html",
    "../src/server/dashboard/index.html",
    "../../src/server/dashboard/index.html",
    "dashboard/index.html",
    NULL
};

/*
 * This constructor runs before main() and loads the dashboard HTML.
 * On MSVC this uses a CRT initializer; on GCC/Clang it uses __attribute__((constructor)).
 */
static void load_dashboard(void) {
    FILE* fp = NULL;

    for (int i = 0; DASHBOARD_PATHS[i]; i++) {
        fp = fopen(DASHBOARD_PATHS[i], "rb");
        if (fp) break;
    }

    if (!fp) {
        /* Provide a minimal fallback */
        static const char fallback[] =
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<title>PromptShield</title></head><body style='background:#0a0b14;color:#e8eaf0;"
            "font-family:system-ui;display:flex;align-items:center;justify-content:center;"
            "min-height:100vh'><div style='text-align:center'>"
            "<h1 style='font-size:2em;margin-bottom:.5em'>&#x1f6e1; PromptShield</h1>"
            "<p>Dashboard HTML not found. Place <code>index.html</code> in the dashboard directory.</p>"
            "<p style='margin-top:1em;opacity:.6'>API is running at <code>/api/v1/</code></p>"
            "</div></body></html>";
        DASHBOARD_HTML = fallback;
        DASHBOARD_HTML_LEN = (unsigned int)(sizeof(fallback) - 1);
        return;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char* buf = (char*)malloc((size_t)fsize + 1);
    if (!buf) {
        fclose(fp);
        return;
    }

    size_t n = fread(buf, 1, (size_t)fsize, fp);
    buf[n] = '\0';
    fclose(fp);

    DASHBOARD_HTML = buf;
    DASHBOARD_HTML_LEN = (unsigned int)n;
}

/* Cross-platform startup initializer */
#if defined(_MSC_VER)
#pragma section(".CRT$XCU", read)
static void __cdecl init_dashboard(void) { load_dashboard(); }
__declspec(allocate(".CRT$XCU")) void (__cdecl *_init_dashboard)(void) = init_dashboard;
#elif defined(__GNUC__) || defined(__clang__)
__attribute__((constructor))
static void init_dashboard(void) { load_dashboard(); }
#else
/* Fallback: must call load_dashboard() manually before starting server */
#endif
