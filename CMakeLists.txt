CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
SET(fw_name "multirat")

PROJECT(${fw_name})

SET(CMAKE_INSTALL_PREFIX /usr)
SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(VERSION_MAJOR 0)
SET(VERSION "${VERSION_MAJOR}.1.0")

SET(INC_DIR include)
SET(CLIENT_INC_DIR client/include)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/client/include)

#SET(requires "dlog capi-base-common download-provider-interface")
#MESSAGE(STATUS "PACKAGES : ${requires}")
#SET(pc_requires "capi-base-common capi-appfw-application")

INCLUDE(FindPkgConfig)
pkg_check_modules(subpkgs REQUIRED
	dlog
	glib-2.0
	dbus-1
	vconf
	dbus-glib-1
	libcares
	capi-network-connection
	capi-network-wifi
)


FOREACH(flag ${subpkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)


SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}  -Wall")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")

IF("${ARCH}" STREQUAL "arm")
    ADD_DEFINITIONS("-DTARGET")
ENDIF("${ARCH}" STREQUAL "arm")

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DSLP_DEBUG")
ADD_DEFINITIONS("-DSB_LOG_SUPPORT")
#ADD_DEFINITIONS("-DSB_DETAIL_LOG_SUPPORT")
ADD_DEFINITIONS("-DTIZEN_UX_SUPPORT")
ADD_DEFINITIONS("-DTWO_CHUNK")

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed -Wl,--rpath=/usr/lib")

SET(SOURCES 
		client/src/smartbonding-client.c
		src/multirat_block_manager.c
		src/multirat_file_manager.c
		src/multirat_data_buffer.c
		src/multirat_file_buffer.c
		src/multirat_multisocket.c
		src/multirat_file_stream.c
		src/multirat_range_request_thread.c
		src/multirat_file_thread.c
		src/multirat_connection.c
		src/multirat_decode_http.c
		src/multirat_process.c
		src/multirat_watch_dog_thread.c
		src/multirat_watchthread.c
		src/multirat_poll_thread.c
		src/multirat_libapi.c
		src/multirat_conf.c)
MESSAGE(STATUS "SOURCES : ${SOURCES}")
ADD_LIBRARY(${fw_name} SHARED ${SOURCES})
#ADD_LIBRARY(${fw_name} STATIC ${SOURCES})


TARGET_LINK_LIBRARIES(${fw_name} ${subpkgs_LDFLAGS})
SET_TARGET_PROPERTIES(${fw_name} PROPERTIES VERSION ${VERSION})
SET_TARGET_PROPERTIES(${fw_name} PROPERTIES SOVERSION ${VERSION_MAJOR})

INSTALL(TARGETS ${fw_name} DESTINATION lib)
INSTALL(
        DIRECTORY ${INC_DIR}/ DESTINATION include/multirat
        FILES_MATCHING
        PATTERN "${INC_DIR}/multirat_process.h"
		PATTERN "${INC_DIR}/multirat_SB_http.h"
        PATTERN "${INC_DIR}/multirat_conf.h"
		PATTERN "${INC_DIR}/multirat_libapi.h"
		)
INSTALL(
	DIRECTORY ${CLIENT_INC_DIR}/ DESTINATION include/multirat
	FILES_MATCHING PATTERN "${CLIENT_INC_DIR}/smartbonding-client.h"
	)

SET(PC_NAME ${fw_name})
SET(PC_REQUIRED ${pc_requires})
SET(PC_LDFLAGS -l${fw_name})
SET(PC_CFLAGS -I\${includedir}/system)

CONFIGURE_FILE(
    multirat.pc.in
    ${CMAKE_CURRENT_SOURCE_DIR}/${fw_name}.pc
    @ONLY
)
#CONFIGURE_FILE(
#	LICENSE.APLv2
#    ${fw_name}
#    @ONLY
#)

INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/${fw_name}.pc DESTINATION lib/pkgconfig)
#INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/${fw_name} DESTINATION share/license)

