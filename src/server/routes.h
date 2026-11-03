/*
 * PromptShield — REST API Server Routes
 * routes.h
 */

#ifndef PS_ROUTES_H
#define PS_ROUTES_H

#include "civetweb.h"
#include "promptshield/promptshield.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Server context passed to all handlers */
typedef struct {
    ps_context_t*       ps_ctx;
    const char*         cors_origin;
    int                 dashboard_enabled;
} server_context_t;

/** Register all API routes on the Civetweb context. */
void routes_register(struct mg_context* mg_ctx, server_context_t* srv_ctx);

#ifdef __cplusplus
}
#endif

#endif /* PS_ROUTES_H */
