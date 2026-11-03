# ── Third-party dependencies ──────────────────────────────────

# cJSON (MIT) — lightweight JSON parser
add_library(cjson STATIC
    cjson/cJSON.c
)
target_include_directories(cjson PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/cjson>
)
add_library(PromptShield::cjson ALIAS cjson)

# Civetweb (MIT) — embedded HTTP server (only when building server)
if(PROMPTSHIELD_BUILD_SERVER)
    add_library(civetweb STATIC
        civetweb/civetweb.c
    )
    target_include_directories(civetweb PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/civetweb>
    )
    target_compile_definitions(civetweb PRIVATE
        NO_SSL             # Disable SSL by default (simplify initial build)
        USE_WEBSOCKET=0
        NO_CGI
        NO_MD5             # Avoid needing md5.inl
        NO_CACHING         # Avoid needing sha1.inl
    )
    if(WIN32)
        target_link_libraries(civetweb PRIVATE ws2_32)
    else()
        target_link_libraries(civetweb PRIVATE pthread)
    endif()
    add_library(PromptShield::civetweb ALIAS civetweb)
endif()
