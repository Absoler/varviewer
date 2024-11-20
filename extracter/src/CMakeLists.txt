
file(GLOB SRCS "*.cpp")


add_executable(extracter ${SRCS})

# 查找并链接 DWARF 库
find_library(DWARF_LIB dwarf)

if(DWARF_LIB)
    target_link_libraries(extracter ${DWARF_LIB})
else()
    message(WARNING "DWARF library not found.")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=leak -g")
