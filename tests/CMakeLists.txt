# ── Tests ──────────────────────────────────────────────────────

# Simple test runner macro
function(ps_add_test TEST_NAME TEST_SOURCE)
    add_executable(${TEST_NAME} ${TEST_SOURCE})
    target_include_directories(${TEST_NAME} PRIVATE
        ${PROJECT_SOURCE_DIR}/src/core
    )
    target_link_libraries(${TEST_NAME} PRIVATE
        PromptShield::core
        PromptShield::cjson
        ${PLATFORM_LIBS}
    )
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME}
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endfunction()

ps_add_test(test_aho_corasick  test_aho_corasick.c)
ps_add_test(test_unicode_norm  test_unicode_norm.c)
ps_add_test(test_statistical   test_statistical.c)
ps_add_test(test_canary          test_canary.c)
ps_add_test(test_context_tracker test_context_tracker.c)
ps_add_test(test_pipeline        test_pipeline.c)
