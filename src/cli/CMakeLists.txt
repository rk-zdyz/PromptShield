# ── CLI Executable ────────────────────────────────────────────

add_executable(promptshield
    main.c
)

target_link_libraries(promptshield
    PRIVATE
        PromptShield::core
        PromptShield::cjson
        ${PLATFORM_LIBS}
)

install(TARGETS promptshield RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
