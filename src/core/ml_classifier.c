/*
 * PromptShield — ML Classifier Layer (ONNX DeBERTa)
 * ml_classifier.c
 *
 * When PS_ENABLE_ONNX is defined, this links against the ONNX Runtime
 * C API to run a DeBERTa binary classifier. Otherwise, all functions
 * return "not available" stubs.
 */

#include "ml_classifier.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ═══════════════════════════════════════════════════════════════
 * ONNX-enabled implementation
 * ═══════════════════════════════════════════════════════════════ */
#ifdef PS_ENABLE_ONNX

#include <onnxruntime_c_api.h>
#include <math.h>

struct ml_context {
    const OrtApi*       api;
    OrtEnv*             env;
    OrtSession*         session;
    OrtSessionOptions*  options;
    OrtMemoryInfo*      memory_info;
    int                 available;
    int                 max_seq_len;
};

ml_context_t* ml_create(const char* model_path, const char* vocab_path) {
    (void)vocab_path;  /* TODO: integrate tokenizer */

    if (!model_path || !model_path[0]) return NULL;

    ml_context_t* ctx = (ml_context_t*)calloc(1, sizeof(ml_context_t));
    if (!ctx) return NULL;

    ctx->api = OrtGetApiBase()->GetApi(ORT_API_VERSION);
    if (!ctx->api) { free(ctx); return NULL; }

    ctx->max_seq_len = 512;

    /* Create environment */
    OrtStatus* status = ctx->api->CreateEnv(ORT_LOGGING_LEVEL_WARNING,
                                             "PromptShield", &ctx->env);
    if (status) { ctx->api->ReleaseStatus(status); free(ctx); return NULL; }

    /* Session options */
    status = ctx->api->CreateSessionOptions(&ctx->options);
    if (status) { ctx->api->ReleaseStatus(status); goto fail; }

    ctx->api->SetIntraOpNumThreads(ctx->options, 1);
    ctx->api->SetSessionGraphOptimizationLevel(ctx->options, ORT_ENABLE_ALL);

    /* Load model */
#ifdef _WIN32
    /* Convert path to wide string for Windows */
    int wlen = MultiByteToWideChar(CP_UTF8, 0, model_path, -1, NULL, 0);
    wchar_t* wpath = (wchar_t*)malloc(wlen * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, model_path, -1, wpath, wlen);
    status = ctx->api->CreateSession(ctx->env, wpath, ctx->options, &ctx->session);
    free(wpath);
#else
    status = ctx->api->CreateSession(ctx->env, model_path, ctx->options, &ctx->session);
#endif
    if (status) { ctx->api->ReleaseStatus(status); goto fail; }

    /* Memory info */
    status = ctx->api->CreateCpuMemoryInfo(OrtArenaAllocator, OrtMemTypeDefault,
                                            &ctx->memory_info);
    if (status) { ctx->api->ReleaseStatus(status); goto fail; }

    ctx->available = 1;
    return ctx;

fail:
    if (ctx->session) ctx->api->ReleaseSession(ctx->session);
    if (ctx->options) ctx->api->ReleaseSessionOptions(ctx->options);
    if (ctx->env)     ctx->api->ReleaseEnv(ctx->env);
    free(ctx);
    return NULL;
}

void ml_destroy(ml_context_t* ctx) {
    if (!ctx) return;
    if (ctx->memory_info) ctx->api->ReleaseMemoryInfo(ctx->memory_info);
    if (ctx->session)     ctx->api->ReleaseSession(ctx->session);
    if (ctx->options)     ctx->api->ReleaseSessionOptions(ctx->options);
    if (ctx->env)         ctx->api->ReleaseEnv(ctx->env);
    free(ctx);
}

ml_result_t ml_classify(ml_context_t* ctx, const char* text, size_t len) {
    ml_result_t r;
    memset(&r, 0, sizeof(r));

    if (!ctx || !ctx->available || !text) {
        snprintf(r.details, sizeof(r.details), "ML classifier not available");
        return r;
    }

    (void)len;

    /*
     * TODO: Implement proper WordPiece tokenization.
     * For now, this is a skeleton that demonstrates the ONNX Runtime
     * inference flow. A production implementation would:
     * 1) Tokenize text with a WordPiece tokenizer (vocab.txt)
     * 2) Create input_ids and attention_mask tensors
     * 3) Run inference
     * 4) Apply softmax to logits
     */
    snprintf(r.details, sizeof(r.details),
             "ML classifier loaded but tokenizer not yet implemented");
    r.available = 1;
    r.safe_prob = 0.5f;
    r.injection_prob = 0.5f;
    r.confidence = 0.5f;
    r.is_injection = 0;

    return r;
}

int ml_is_available(const ml_context_t* ctx) {
    return (ctx && ctx->available) ? 1 : 0;
}

/* ═══════════════════════════════════════════════════════════════
 * Stub implementation (no ONNX)
 * ═══════════════════════════════════════════════════════════════ */
#else /* !PS_ENABLE_ONNX */

struct ml_context {
    int dummy;
};

ml_context_t* ml_create(const char* model_path, const char* vocab_path) {
    (void)model_path;
    (void)vocab_path;
    return NULL;
}

void ml_destroy(ml_context_t* ctx) {
    (void)ctx;
}

ml_result_t ml_classify(ml_context_t* ctx, const char* text, size_t len) {
    (void)ctx; (void)text; (void)len;
    ml_result_t r;
    memset(&r, 0, sizeof(r));
    snprintf(r.details, sizeof(r.details), "ML classifier not compiled (ONNX disabled)");
    return r;
}

int ml_is_available(const ml_context_t* ctx) {
    (void)ctx;
    return 0;
}

#endif /* PS_ENABLE_ONNX */
