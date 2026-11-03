# ── Core Library (libpromptshield) ─────────────────────────────

set(CORE_SOURCES
    aho_corasick.c
    unicode_norm.c
    statistical.c
    canary.c
    context_tracker.c
    ml_classifier.c
    config.c
    utils.c
    pipeline.c
)

add_library(promptshield_core STATIC ${CORE_SOURCES})

target_include_directories(promptshield_core
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(promptshield_core
    PUBLIC  PromptShield::cjson
    PRIVATE ${PLATFORM_LIBS}
)

# ONNX Runtime (optional)
if(PROMPTSHIELD_ENABLE_ONNX)
    target_link_libraries(promptshield_core PRIVATE OnnxRuntime::OnnxRuntime)
endif()

# Suppress MSVC warnings in third-party-dependent code
if(MSVC)
    target_compile_options(promptshield_core PRIVATE /wd4244 /wd4267)
endif()

add_library(PromptShield::core ALIAS promptshield_core)
