# ═══════════════════════════════════════════════════════════════
# PromptShield — Prompt Injection Firewall
# Root CMakeLists.txt
# ═══════════════════════════════════════════════════════════════
cmake_minimum_required(VERSION 3.20)

project(PromptShield
    VERSION 1.0.0
    DESCRIPTION "Native C prompt injection firewall"
    LANGUAGES C
)

# ── C Standard ────────────────────────────────────────────────
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ── Build options ─────────────────────────────────────────────
option(PROMPTSHIELD_ENABLE_ONNX   "Enable ONNX DeBERTa ML classifier layer"  OFF)
option(PROMPTSHIELD_BUILD_TESTS   "Build unit tests"                          ON)
option(PROMPTSHIELD_BUILD_SERVER  "Build REST API server + dashboard"         ON)
option(PROMPTSHIELD_BUILD_CLI     "Build CLI tool"                            ON)

# ── Platform detection ────────────────────────────────────────
if(WIN32)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    # Link Winsock for Civetweb
    set(PLATFORM_LIBS ws2_32)
else()
    set(PLATFORM_LIBS m pthread)
endif()

# ── Compiler warnings ────────────────────────────────────────
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# ── ONNX Runtime (optional) ──────────────────────────────────
if(PROMPTSHIELD_ENABLE_ONNX)
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
    find_package(OnnxRuntime REQUIRED)
    add_compile_definitions(PS_ENABLE_ONNX=1)
endif()

# ── Subdirectories ────────────────────────────────────────────
add_subdirectory(third_party)
add_subdirectory(src/core)

if(PROMPTSHIELD_BUILD_CLI)
    add_subdirectory(src/cli)
endif()

if(PROMPTSHIELD_BUILD_SERVER)
    add_subdirectory(src/server)
endif()

if(PROMPTSHIELD_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ── Install rules ────────────────────────────────────────────
include(GNUInstallDirs)

install(DIRECTORY include/promptshield
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY data/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/promptshield
)
