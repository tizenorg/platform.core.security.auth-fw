PKG_CHECK_MODULES(COMMON_DEP
    REQUIRED
    dlog
    )

SET(COMMON_SOURCES
    error-description.cpp
    message-buffer.cpp
    policy.cpp
    protocols.cpp
    ${DPL_PATH}/core/src/assert.cpp
    ${DPL_PATH}/core/src/binary_queue.cpp
    ${DPL_PATH}/core/src/colors.cpp
    ${DPL_PATH}/core/src/exception.cpp
    ${DPL_PATH}/core/src/serialization.cpp
    ${DPL_PATH}/core/src/singleton.cpp
    ${DPL_PATH}/log/src/abstract_log_provider.cpp
    ${DPL_PATH}/log/src/dlog_log_provider.cpp
    ${DPL_PATH}/log/src/log.cpp
    ${DPL_PATH}/log/src/old_style_log_provider.cpp
    )

INCLUDE_DIRECTORIES(
    SYSTEM
    ${COMMON_DEP_INCLUDE_DIRS}
    ${INCLUDE_PATH}
    ${COMMON_PATH}/include
    ${PLUGIN_PATH}/include
    ${DPL_PATH}/core/include
    ${DPL_PATH}/log/include
    )

ADD_LIBRARY(${TARGET_COMMON} SHARED ${COMMON_SOURCES})

SET_TARGET_PROPERTIES(${TARGET_COMMON}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=hidden"
        SOVERSION ${API_VERSION}
        VERSION ${VERSION}
    )

TARGET_LINK_LIBRARIES(${TARGET_COMMON} ${COMMON_DEP_LIBRARIES})

INSTALL(TARGETS ${TARGET_COMMON} DESTINATION ${LIB_INSTALL_DIR})
