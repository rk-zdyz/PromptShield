# ── REST API Server ────────────────────────────────────────────

add_executable(promptshield-server
    main.c
    routes.c
    dashboard_html.c
)

target_include_directories(promptshield-server
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/src/core
)

target_link_libraries(promptshield-server
    PRIVATE
        PromptShield::core
        PromptShield::civetweb
        PromptShield::cjson
        ${PLATFORM_LIBS}
)

install(TARGETS promptshield-server RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# Copy dashboard files to build directory for runtime loading
add_custom_command(TARGET promptshield-server POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/dashboard
        $<TARGET_FILE_DIR:promptshield-server>/dashboard
    COMMENT "Copying dashboard files..."
)
