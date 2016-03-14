PKG_CHECK_MODULES(COMMON_DEP
    REQUIRED
    dlog
    libsmack
    )

SET(COMMON_SOURCES
    ${COMMON_PATH}/error-description.cpp
    ${COMMON_PATH}/protocols.cpp
    ${COMMON_PATH}/policy.cpp
    ${COMMON_PATH}/message-buffer.cpp
    ${COMMON_PATH}/smack-check.cpp
    ${COMMON_PATH}/user-check.cpp
    ${DPL_PATH}/log/src/abstract_log_provider.cpp
    ${DPL_PATH}/log/src/dlog_log_provider.cpp
    ${DPL_PATH}/log/src/log.cpp
    ${DPL_PATH}/log/src/old_style_log_provider.cpp
    ${DPL_PATH}/core/src/assert.cpp
    ${DPL_PATH}/core/src/binary_queue.cpp
    ${DPL_PATH}/core/src/colors.cpp
    ${DPL_PATH}/core/src/exception.cpp
    ${DPL_PATH}/core/src/noncopyable.cpp
    ${DPL_PATH}/core/src/serialization.cpp
    ${DPL_PATH}/core/src/singleton.cpp
    )

SET_SOURCE_FILES_PROPERTIES(
    ${COMMON_SOURCES}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=default" #TODO: visibility hidden
    )

INCLUDE_DIRECTORIES(SYSTEM
    ${COMMON_DEP_INCLUDE_DIRS}
    )

INCLUDE_DIRECTORIES(
    ${INCLUDE_PATH}
    ${COMMON_PATH}/include
    ${PLUGIN_PATH}/include
    ${DPL_PATH}/core/include
    ${DPL_PATH}/log/include
    )

ADD_LIBRARY(${TARGET_COMMON} SHARED ${COMMON_SOURCES})

SET_TARGET_PROPERTIES(
    ${TARGET_COMMON}
    PROPERTIES
        SOVERSION 1.0.0 #TODO: version tracking by rpm spec version specification
        VERSION 1.0.0
    )

TARGET_LINK_LIBRARIES(${TARGET_COMMON}
    ${COMMON_DEP_LIBRARIES}
    )

INSTALL(TARGETS ${TARGET_COMMON} DESTINATION ${LIB_INSTALL_DIR})
