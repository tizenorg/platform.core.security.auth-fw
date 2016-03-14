INCLUDE_DIRECTORIES(
    ${INCLUDE_PATH}
    ${COMMON_PATH}/include
    ${CLIENT_PATH}/include
    ${DPL_PATH}/core/include
    ${DPL_PATH}/log/include
    )

SET(CLIENT_SOURCES
    client-common.cpp
    client-password.cpp
    )

ADD_LIBRARY(${TARGET_CLIENT} SHARED ${CLIENT_SOURCES})

SET_TARGET_PROPERTIES(
    ${TARGET_CLIENT}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=hidden"
        SOVERSION ${API_VERSION}
        VERSION ${VERSION}
    )

TARGET_LINK_LIBRARIES(${TARGET_CLIENT} ${TARGET_COMMON})

INSTALL(TARGETS ${TARGET_CLIENT} DESTINATION ${LIB_INSTALL_DIR})

################################################################################

INCLUDE_DIRECTORIES(
    ${INCLUDE_PATH}
    ${COMMON_PATH}/include
    ${CLIENT_PATH}/include
    ${DPL_PATH}/core/include
    ${DPL_PATH}/log/include
    )

SET(CLIENT_ADMIN_SOURCES
    client-common.cpp
    client-password-admin.cpp
    )

ADD_LIBRARY(${TARGET_CLIENT_ADMIN} SHARED ${CLIENT_ADMIN_SOURCES})

SET_TARGET_PROPERTIES(
    ${TARGET_CLIENT_ADMIN}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=hidden"
        SOVERSION ${API_VERSION}
        VERSION ${VERSION}
    )

TARGET_LINK_LIBRARIES(${TARGET_CLIENT_ADMIN} ${TARGET_COMMON})

INSTALL(TARGETS ${TARGET_CLIENT_ADMIN} DESTINATION ${LIB_INSTALL_DIR})
