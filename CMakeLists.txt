cmake_minimum_required(VERSION 3.10)
project(SantaOsqueryExtension)

# Use C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set the root directory for osquery
set(OSQUERY_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/osquery)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    /usr/local/include
)

# Find SQLite (required for santa.cpp)
find_package(SQLite3 REQUIRED)
include_directories(${SQLite3_INCLUDE_DIRS})

# Find Boost components
find_package(Boost REQUIRED COMPONENTS filesystem iostreams process)
include_directories(${Boost_INCLUDE_DIRS})

# List all source files but exclude the main implementation files
# that need osquery deep integration
set(SOURCES
    santa.cpp
    utils.cpp
)

# Build a simple test app to verify parts of the code work
add_executable(santa_test ${SOURCES} santa_test.cpp)

target_link_libraries(santa_test
    ${SQLite3_LIBRARIES}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_IOSTREAMS_LIBRARY}
    ${Boost_PROCESS_LIBRARY}
)