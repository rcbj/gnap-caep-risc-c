# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.16)
project(iya_gnap LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_library(iya_gnap STATIC
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
target_include_directories(iya_gnap PUBLIC include PRIVATE src)
target_link_libraries(iya_gnap PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
set_target_properties(iya_gnap PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_executable(gnap_c_tests tests/c_tests.c tests/harness.cpp)
target_include_directories(gnap_c_tests PRIVATE tests src include)
target_link_libraries(gnap_c_tests PRIVATE iya_gnap)
set_target_properties(gnap_c_tests PROPERTIES LINKER_LANGUAGE CXX)

add_executable(gnap_cpp_smoke tests/cpp_smoke.cpp)
target_link_libraries(gnap_cpp_smoke PRIVATE iya_gnap)

add_executable(gnap-demo src/demo_main.cpp)
target_include_directories(gnap-demo PRIVATE src include)
target_link_libraries(gnap-demo PRIVATE iya_gnap)

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
add_test(NAME CppSmoke COMMAND gnap_cpp_smoke)
