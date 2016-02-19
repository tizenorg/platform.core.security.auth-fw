INSTALL(FILES
    ${CMAKE_SOURCE_DIR}/systemd/authentication-server.service
    ${CMAKE_SOURCE_DIR}/systemd/authentication-server.target
    ${CMAKE_SOURCE_DIR}/systemd/authentication-server-passwd-check.socket
    ${CMAKE_SOURCE_DIR}/systemd/authentication-server-passwd-set.socket
    ${CMAKE_SOURCE_DIR}/systemd/authentication-server-passwd-reset.socket
    ${CMAKE_SOURCE_DIR}/systemd/authentication-server-passwd-policy.socket
    DESTINATION
    /usr/lib/systemd/system
)

