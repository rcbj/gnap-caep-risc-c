# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.16)

# The version is VERSION's, so the library, the package and the release tag agree.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" IYA_GNAP_VERSION)
string(STRIP "${IYA_GNAP_VERSION}" IYA_GNAP_VERSION)
project(iya_gnap VERSION ${IYA_GNAP_VERSION} LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# On when this is the top-level project (a checkout, the Docker test stage); a package
# build (a Conan recipe, add_subdirectory) turns them off and gets the library alone.
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  set(IYA_GNAP_TOP_LEVEL ON)
else()
  set(IYA_GNAP_TOP_LEVEL OFF)
endif()
option(IYA_GNAP_BUILD_TESTS "Build the tests" ${IYA_GNAP_TOP_LEVEL})
option(IYA_GNAP_BUILD_PROGRAMS "Build the demo and the command-line programs" ${IYA_GNAP_TOP_LEVEL})

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Static or shared as BUILD_SHARED_LIBS says (static when it is unset).
add_library(iya_gnap
  src/json.cpp
  src/url.cpp
  src/codec.cpp
  src/crypto.cpp
  src/http.cpp
  src/config.cpp
  src/subject.cpp
  src/client.cpp
  src/receiver.cpp
  src/c_api.cpp)
add_library(iya::gnap ALIAS iya_gnap)
target_include_directories(iya_gnap
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(iya_gnap PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
# The C++ headers need C++17; a consumer gets that from the target.
target_compile_features(iya_gnap PUBLIC cxx_std_17)
set_target_properties(iya_gnap PROPERTIES
  EXPORT_NAME gnap
  POSITION_INDEPENDENT_CODE ON
  VERSION ${PROJECT_VERSION}
  # 0.x: every minor version may break the ABI.
  SOVERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR})

# The library, its public headers (include/ holds nothing else), and a CMake package:
#   find_package(iya_gnap REQUIRED)
#   target_link_libraries(app PRIVATE iya::gnap)
install(TARGETS iya_gnap EXPORT iya_gnapTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT iya_gnapTargets NAMESPACE iya:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/iya_gnap)
configure_package_config_file(cmake/iya_gnapConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/iya_gnapConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/iya_gnap)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/iya_gnapConfigVersion.cmake
  COMPATIBILITY SameMinorVersion)
install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/iya_gnapConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/iya_gnapConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/iya_gnap)

if(IYA_GNAP_BUILD_PROGRAMS OR IYA_GNAP_BUILD_TESTS)
add_executable(gnap-demo src/demo_main.cpp)
target_include_directories(gnap-demo PRIVATE src include)
target_link_libraries(gnap-demo PRIVATE iya_gnap)
endif()

if(IYA_GNAP_BUILD_TESTS)
add_executable(gnap_c_tests tests/c_tests.c tests/harness.cpp)
target_include_directories(gnap_c_tests PRIVATE tests src include)
target_link_libraries(gnap_c_tests PRIVATE iya_gnap)
set_target_properties(gnap_c_tests PROPERTIES LINKER_LANGUAGE CXX)
add_executable(gnap_trust_tests tests/trust.cpp)
target_include_directories(gnap_trust_tests PRIVATE src include)
target_link_libraries(gnap_trust_tests PRIVATE iya_gnap OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
add_executable(gnap_cpp_smoke tests/cpp_smoke.cpp)
target_link_libraries(gnap_cpp_smoke PRIVATE iya_gnap)
enable_testing()
set(IYA_GNAP_CTESTS
  TestDefaultsAccessAndFillsTransmitter
  TestDropsSSFRightsAndTransmitterWhenSignalsIsFalse
  TestRefusesSignalsOffWhenSSFRightsWereTheOnlyOnes
  TestRefusesASignalsValueThatIsNotTrueOrFalse
  TestInteractionHashVector
  TestRefusesFrontChannelForeignAndAHashThatIsNotOurs
  TestFinishesARedirectChecksTheIDTokenAndRotates
  TestProvesTheKeyWithDetachedJWSAndMutualTLS
  TestRefusesBearerBadAudienceAndASubjectThatDoesNotMatch
  TestAcceptsTheApplicationIdentifierAsTheIDTokenAudience
  TestCertificateChainPutsTheLeafInTheKeyAndTheChainOnTLS
  TestUIDFromAccountKeepsTheProtocolSubject
  TestPercentDecodesTheUserPartAndKeepsInvalidEncoding
  TestUIDStaysUnsetWithoutAnAccountIdentifier
  TestVerifiesASETAndRefusesAnotherKey
  TestReadsSubjectForms
  TestPollsWithTheGNAPTokenAndAcknowledges)
foreach(name ${IYA_GNAP_CTESTS})
  add_test(NAME ${name} COMMAND gnap_c_tests ${name})
endforeach()
# tlsCa, the host name, the forged leaf, the mtls client certificate, and trust_chain.py.
set(IYA_GNAP_TRUST_TESTS
  TestTlsCaChainIsTheTrustStore
  TestAForgedLeafBeforeTheRealCaIsRefused
  TestHostNameIsChecked
  TestHostNameIsCheckedWithoutTlsCa
  TestClientPresentsItsSelfSignedCertWhenTheCaListNamesAnother
  TestConfigureWritesTheWholeChain)
foreach(name ${IYA_GNAP_TRUST_TESTS})
  add_test(NAME ${name} COMMAND gnap_trust_tests ${name})
  set_tests_properties(${name} PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} TIMEOUT 180)
endforeach()
add_test(NAME CppSmoke COMMAND gnap_cpp_smoke)
endif()
