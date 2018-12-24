cmake_minimum_required(VERSION 3.5)

project(smf-spf C)

# Executable name
set(EXE smf-spf)
# Sources
set(SRC smf-spf.c)
# User/group name for installation
set(SMFS smfs)

# Main program
add_executable(${EXE} ${SRC})

# Compiler flags
if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  include(CheckCCompilerFlag)
  check_c_compiler_flag(-fomit-frame-pointer FLAG_OFP)
  if(FLAG_OFP)
    target_compile_options(${EXE} PRIVATE -fomit-frame-pointer)
  endif()
endif()

target_compile_options(${EXE}
  PRIVATE
    $<$<CONFIG:Debug>:-O0>
    ${OPTFLAGS}
    -Wall -Wextra -pedantic
  )

# Link libraries
# pthreads
set(THREADS_PREFER_PTHREAD_FLAG ON)
set(CMAKE_THREAD_PREFER_PTHREAD ON)
find_package(Threads REQUIRED)
target_link_libraries(${EXE} Threads::Threads) # sets -D_REENTRANT

# libmilter
find_library(LIBMILTER milter)
if(NOT LIBMILTER)
  message(FATAL_EROR "libmilter not found")
endif()
find_file(MFAPI_H libmilter/mfapi.h)
if(NOT MFAPI_H)
  message(FATAL_ERROR "libmilter/mfapi.h not found")
endif()
target_link_libraries(${EXE} ${LIBMILTER})

# libspf2
find_library(LIBSPF2 spf2)
if(NOT LIBSPF2)
  message(FATAL_ERROR "libspf2 not found")
endif()
find_file(SPF_H spf2/spf.h)
if(NOT SPF_H)
  message(FATAL_ERROR "spf2/spf.h not found")
endif()
target_link_libraries(${EXE} ${LIBSPF2})

# Installation
include(GNUInstallDirs)
install(TARGETS ${EXE} DESTINATION ${CMAKE_INSTALL_SBINDIR})
install(DIRECTORY
  DESTINATION ${CMAKE_INSTALL_LOCALSTATEDIR}/run
  DIRECTORY_PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
  )
install(CODE
"execute_process(COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/add-smfs-user.sh)
  execute_process(COMMAND
    chown ${SMFS}:${SMFS} ${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/run
    )"
)
install(FILES ${EXE}.conf 
  DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/mail/${SMFS}
  RENAME ${EXE}.conf.default
  )
