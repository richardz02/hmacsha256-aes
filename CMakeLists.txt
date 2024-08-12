cmake_minimum_required(VERSION 3.28.3)

project(hmacsha256-aes)

include_directories(/usr/local/include/cryptopp)

file(GLOB_RECURSE LIB_SRC "lib/*")

set(
  SOURCES
  ${LIB_SRC}
)

set(
  EXES
  exes/client.cpp
  exes/server.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES} ${EXES})

target_link_libraries(
  ${PROJECT_NAME}
  /usr/local/lib/libcryptopp.a
)

set_target_properties(
  ${PROJECT_NAME} PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED YES
)
