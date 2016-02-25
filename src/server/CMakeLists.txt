PKG_CHECK_MODULES(SERVER_DEP
    dlog
    openssl
    libsmack
    libsystemd-daemon
    libtzplatform-config
    REQUIRED
    )
FIND_PACKAGE(Threads REQUIRED)

INCLUDE_DIRECTORIES(SYSTEM
    ${SERVER_DEP_INCLUDE_DIRS}
    )

INCLUDE_DIRECTORIES(
    ${INCLUDE_PATH}
    ${COMMON_PATH}/include
    ${SERVER_PATH}/main/include
    ${SERVER_PATH}/service/include
    ${DPL_PATH}/core/include
    ${DPL_PATH}/log/include
    )

SET(SERVER_SOURCES
    ${SERVER_PATH}/main/generic-socket-manager.cpp
    ${SERVER_PATH}/main/socket-manager.cpp
    ${SERVER_PATH}/main/server-main.cpp
    ${SERVER_PATH}/service/password.cpp
    ${SERVER_PATH}/service/password-file.cpp
    ${SERVER_PATH}/service/password-manager.cpp
    ${SERVER_PATH}/service/password-file-buffer.cpp
    ${SERVER_PATH}/service/policy-manager.cpp
    ${SERVER_PATH}/service/policy-file.cpp
    )

SET_SOURCE_FILES_PROPERTIES(
    ${SERVER_SOURCES}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fvisibility=hidden -fPIE")

ADD_EXECUTABLE(${TARGET_SERVER} ${SERVER_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_SERVER}
    ${TARGET_COMMON}
    ${CMAKE_THREAD_LIBS_INIT}
    ${SERVER_DEP_LIBRARIES} -pie -ldl
    )

INSTALL(TARGETS ${TARGET_SERVER}
    DESTINATION bin
    PERMISSIONS
        OWNER_READ
        OWNER_WRITE
        OWNER_EXECUTE
        GROUP_READ
        GROUP_EXECUTE
        WORLD_READ
        WORLD_EXECUTE
    )
