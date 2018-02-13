set(CMAKE_CXX_FLAGS "-pthread")

if(BUILD_SHARED_LIBS)
	find_library(M_LIB m)
endif()

include_directories(
	.
	curve25519/ed25519/nacl_includes
	curve25519/ed25519/additions
	curve25519/ed25519/sha512
	curve25519/ed25519
	curve25519
)

find_package(Threads)
set(LIBS ${LIBS}
	${M_LIB}
	${CHECK_LDFLAGS}
	${OPENSSL_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT}
	${CMAKE_DL_LIBS}
	signal-protocol-c
)

set(protobuf_SRCS
	LocalStorageProtocol.pb-c.c
	WhisperTextProtocol.pb-c.c
	FingerprintProtocol.pb-c.c
)

set(signal_protocol_SRCS
	vpool.c
	vpool.h
	signal_protocol.c
	signal_protocol.h
	signal_protocol_types.h
	signal_protocol_internal.h
	curve.c
	curve.h
	hkdf.c
	hkdf.h
	ratchet.c
	ratchet.h
	protocol.c
	protocol.h
	session_state.c
	session_state.h
	session_record.c
	session_record.h
	session_pre_key.c
	session_pre_key.h
	session_builder.c
	session_builder.h
	session_builder_internal.h
	session_cipher.c
	session_cipher.h
	key_helper.c
	key_helper.h
	sender_key.c
	sender_key.h
	sender_key_state.c
	sender_key_state.h
	sender_key_record.c
	sender_key_record.h
	group_session_builder.c
	group_session_builder.h
	group_cipher.c
	group_cipher.h
	fingerprint.c
	fingerprint.h
	device_consistency.c
	device_consistency.h
	Codistan/test_protocol.c
	Codistan/signal_protocol_overrides.c
	Codistan/signal_protocol_overrides.h
)

#set(codistan_src
#	Codistan/test_protocol.c
#	Codistan/signal_protocol_overrides.c
#	Codistan/signal_protocol_overrides.h
#)

#add_library(codistan_lib
#	${codistan_src}
#)

add_subdirectory(curve25519)
add_subdirectory(protobuf-c)

add_library(signal-protocol-c
	${protobuf_SRCS}
	${signal_protocol_SRCS}
	$<TARGET_OBJECTS:curve25519>
	$<TARGET_OBJECTS:protobuf-c>
)

if(BUILD_SHARED_LIBS)
	target_link_libraries(signal-protocol-c ${M_LIB})
	set_target_properties(signal-protocol-c PROPERTIES
		VERSION ${SIGNAL_PROTOCOL_C_VERSION}
		SOVERSION ${SIGNAL_PROTOCOL_C_VERSION_MAJOR}
	)
endif()

INSTALL(
	FILES
	signal_protocol.h
	signal_protocol_types.h
	curve.h
	hkdf.h
	ratchet.h
	protocol.h
	session_state.h
	session_record.h
	session_pre_key.h
	session_builder.h
	session_cipher.h
	key_helper.h
	sender_key.h
	sender_key_state.h
	sender_key_record.h
	group_session_builder.h
	group_cipher.h
	fingerprint.h
	device_consistency.h
	DESTINATION ${INCLUDE_INSTALL_DIR}/signal
)

INSTALL(TARGETS signal-protocol-c
	LIBRARY DESTINATION ${LIB_INSTALL_DIR}
	RUNTIME DESTINATION ${BIN_INSTALL_DIR}
	ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
)

configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/libsignal-protocol-c.pc.in
		${CMAKE_CURRENT_BINARY_DIR}/libsignal-protocol-c.pc @ONLY)

INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/libsignal-protocol-c.pc DESTINATION "${INSTALL_PKGCONFIG_DIR}")

# Codistan
add_executable(hello Codistan/hello_libsignal.c)
add_executable(codistan_test Codistan/test_protocol.c)
target_link_libraries(codistan_test signal-protocol-c m ${LIBS})