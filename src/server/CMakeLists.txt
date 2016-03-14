PKG_CHECK_MODULES(SERVER_DEP
    REQUIRED
    libsmack
    libsystemd-daemon
    openssl
    )

FIND_PACKAGE(Threads REQUIRED)

INCLUDE_DIRECTORIES(
    SYSTEM
    ${SERVER_DEP_INCLUDE_DIRS}
    ${INCLUDE_PATH}
    ${COMMON_PATH}/include
    ${SERVER_PATH}/main/include
    ${SERVER_PATH}/service/include
    ${DPL_PATH}/core/include
    ${DPL_PATH}/log/include
    )

SET(SERVER_SOURCES
    main/generic-socket-manager.cpp
    main/server-main.cpp
    main/smack-check.cpp
    main/socket-manager.cpp
    main/user-check.cpp
    service/password.cpp
    service/password-file-buffer.cpp
    service/password-file.cpp
    service/password-manager.cpp
    service/policy-file.cpp
    service/policy-manager.cpp
    )

SET_SOURCE_FILES_PROPERTIES(${SERVER_SOURCES}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fvisibility=hidden -fPIE"
    )

ADD_EXECUTABLE(${TARGET_SERVER} ${SERVER_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_SERVER}
    ${TARGET_COMMON}
    ${CMAKE_THREAD_LIBS_INIT}
    ${SERVER_DEP_LIBRARIES}
    -pie
    -ldl
    )

INSTALL(TARGETS ${TARGET_SERVER}
    DESTINATION ${BIN_DIR}
    PERMISSIONS
        OWNER_READ
        OWNER_WRITE
        OWNER_EXECUTE
        GROUP_READ
        GROUP_EXECUTE
        WORLD_READ
        WORLD_EXECUTE
    )
