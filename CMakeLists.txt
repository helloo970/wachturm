cmake_minimum_required(VERSION 3.21)

project(Wachturm VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(WT_BUILD_TESTS "Unit-Tests (Catch2) bauen" ON)
option(WT_WITH_YARA   "YARA-Unterstuetzung, falls libyara gefunden wird" ON)

# ---------------------------------------------------------------------------
# Abhaengigkeiten (kommen ueber vcpkg, siehe vcpkg.json)
# ---------------------------------------------------------------------------
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_path(STB_INCLUDE_DIRS "stb_image.h" REQUIRED)

set(WT_HAVE_YARA OFF)
if(WT_WITH_YARA)
    find_path(YARA_INCLUDE_DIR yara.h)
    find_library(YARA_LIBRARY NAMES libyara yara)
    if(YARA_INCLUDE_DIR AND YARA_LIBRARY)
        set(WT_HAVE_YARA ON)
        message(STATUS "YARA gefunden: ${YARA_LIBRARY}")
    else()
        message(WARNING "libyara nicht gefunden - YARA-Scans sind deaktiviert.")
    endif()
endif()

# ---------------------------------------------------------------------------
# Kern-Bibliothek (alles ausser main) - wird von Programm UND Tests benutzt
# ---------------------------------------------------------------------------
add_library(wachturm_core STATIC
    src/core/Config.cpp
    src/core/Console.cpp
    src/core/Logger.cpp
    src/net/Socket.cpp
    src/net/Targets.cpp
    src/net/HostDiscovery.cpp
    src/net/PortScanner.cpp
    src/net/ServiceAudit.cpp
    src/fim/Hashing.cpp
    src/fim/Entropy.cpp
    src/fim/Baseline.cpp
    src/fim/YaraScanner.cpp
    src/fim/Detector.cpp
    src/quarantine/Quarantine.cpp
    src/report/Report.cpp
    src/ui/Banner.cpp
    src/ui/Progress.cpp
    src/ui/stb_impl.cpp
)

target_include_directories(wachturm_core PUBLIC src ${STB_INCLUDE_DIRS})
target_link_libraries(wachturm_core PUBLIC
    Threads::Threads
    OpenSSL::Crypto
    ZLIB::ZLIB
    nlohmann_json::nlohmann_json
)
target_compile_definitions(wachturm_core PUBLIC WT_VERSION="${PROJECT_VERSION}")

if(WT_HAVE_YARA)
    target_include_directories(wachturm_core PRIVATE ${YARA_INCLUDE_DIR})
    target_link_libraries(wachturm_core PUBLIC ${YARA_LIBRARY})
    target_compile_definitions(wachturm_core PUBLIC WT_HAVE_YARA=1)
endif()

if(WIN32)
    target_link_libraries(wachturm_core PUBLIC ws2_32 iphlpapi)
    target_compile_definitions(wachturm_core PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
endif()

if(MSVC)
    # /utf-8 ist wichtig: Umlaute und Rahmenzeichen im Quellcode sind UTF-8
    target_compile_options(wachturm_core PUBLIC /W4 /utf-8 /permissive- /EHsc)
else()
    target_compile_options(wachturm_core PUBLIC -Wall -Wextra -Wpedantic)
endif()

# ---------------------------------------------------------------------------
# Programm
# ---------------------------------------------------------------------------
add_executable(wachturm src/main.cpp)
target_link_libraries(wachturm PRIVATE wachturm_core)
if(WIN32)
    target_link_libraries(wachturm PRIVATE shell32)  # CommandLineToArgvW
endif()

# Eigenes Logo: liegt logo.png im Projektordner, wird es neben die .exe kopiert
if(EXISTS ${CMAKE_SOURCE_DIR}/logo.png)
    add_custom_command(TARGET wachturm POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${CMAKE_SOURCE_DIR}/logo.png $<TARGET_FILE_DIR:wachturm>/logo.png)
endif()

# Beispiel-Dateien neben die .exe kopieren
add_custom_command(TARGET wachturm POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_SOURCE_DIR}/config/config.json $<TARGET_FILE_DIR:wachturm>/config.json
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_SOURCE_DIR}/config/blacklist.txt $<TARGET_FILE_DIR:wachturm>/blacklist.txt
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/rules $<TARGET_FILE_DIR:wachturm>/rules
)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(WT_BUILD_TESTS)
    find_package(Catch2 3 CONFIG REQUIRED)
    enable_testing()
    add_executable(wachturm_tests
        tests/test_targets.cpp
        tests/test_fim.cpp
        tests/test_quarantine.cpp
        tests/test_threadpool.cpp
    )
    target_link_libraries(wachturm_tests PRIVATE wachturm_core Catch2::Catch2WithMain)
    include(Catch)
    catch_discover_tests(wachturm_tests)
endif()
