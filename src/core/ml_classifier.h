/*
 * PromptShield — ML Classifier Layer (ONNX DeBERTa)
 * ml_classifier.h
 */

#ifndef PS_ML_CLASSIFIER_H
#define PS_ML_CLASSIFIER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** ML classification result */
typedef struct {
    float   safe_prob;          /* P(safe) */
    float   injection_prob;     /* P(injection) */
    float   confidence;         /* max(safe_prob, injection_prob) */
    int     is_injection;       /* 1 if classified as injection */
    int     available;          /* 1 if ML model was loaded and used */
    char    details[256];
} ml_result_t;

/** Opaque ML classifier context */
typedef struct ml_context ml_context_t;

/**
 * Create an ML classifier context.
 * @param model_path   Path to ONNX model file.
 * @param vocab_path   Path to tokenizer vocabulary.
 * @return Context handle, or NULL if ONNX not available.
 */
ml_context_t* ml_create(const char* model_path, const char* vocab_path);

/** Destroy the ML context. */
void ml_destroy(ml_context_t* ctx);

/**
 * Classify text using the DeBERTa model.
 * @param ctx    ML context.
 * @param text   Input text.
 * @param len    Text length (0 = strlen).
 * @return Classification result.
 */
ml_result_t ml_classify(ml_context_t* ctx, const char* text, size_t len);

/** Check if ML classification is available. */
int ml_is_available(const ml_context_t* ctx);

#ifdef __cplusplus
}
#endif

#endif /* PS_ML_CLASSIFIER_H */
