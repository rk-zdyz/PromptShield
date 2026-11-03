# ── Find ONNX Runtime ─────────────────────────────────────────
#
# Searches for the ONNX Runtime C API.
# Set ONNXRUNTIME_ROOT to the installation directory.
#
# Defines:
#   OnnxRuntime_FOUND
#   OnnxRuntime::OnnxRuntime  (imported target)
#

find_path(ONNXRUNTIME_INCLUDE_DIR
    NAMES onnxruntime_c_api.h
    PATHS
        ${ONNXRUNTIME_ROOT}/include
        $ENV{ONNXRUNTIME_ROOT}/include
        /usr/local/include/onnxruntime
        /usr/include/onnxruntime
)

find_library(ONNXRUNTIME_LIBRARY
    NAMES onnxruntime
    PATHS
        ${ONNXRUNTIME_ROOT}/lib
        $ENV{ONNXRUNTIME_ROOT}/lib
        /usr/local/lib
        /usr/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(OnnxRuntime
    REQUIRED_VARS ONNXRUNTIME_LIBRARY ONNXRUNTIME_INCLUDE_DIR
)

if(OnnxRuntime_FOUND AND NOT TARGET OnnxRuntime::OnnxRuntime)
    add_library(OnnxRuntime::OnnxRuntime SHARED IMPORTED)
    set_target_properties(OnnxRuntime::OnnxRuntime PROPERTIES
        IMPORTED_LOCATION "${ONNXRUNTIME_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${ONNXRUNTIME_INCLUDE_DIR}"
    )
endif()
