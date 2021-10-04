cmake_minimum_required(VERSION 3.10)

project(pam_nthash)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

set(SRC_FILES
	src/pam_nthash.c
	src/md4.c)

find_package(ICU COMPONENTS uc REQUIRED)

add_library(pam_nthash SHARED ${SRC_FILES})

set_target_properties(pam_nthash PROPERTIES PREFIX "")

target_compile_options(pam_nthash PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion)

target_link_libraries(pam_nthash keyutils)
target_link_libraries(pam_nthash ICU::uc)

install(TARGETS pam_nthash DESTINATION /${CMAKE_INSTALL_LIBDIR}/security)
