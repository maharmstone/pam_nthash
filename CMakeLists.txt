cmake_minimum_required(VERSION 3.10)

project(pam_ntlm)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

set(SRC_FILES
	src/pam_ntlm.c)

add_library(pam_ntlm SHARED ${SRC_FILES})

set_target_properties(pam_ntlm PROPERTIES PREFIX "")

target_compile_options(pam_ntlm PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion)
target_link_libraries(pam_ntlm keyutils)
