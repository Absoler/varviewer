file(GLOB SRCS "*.cpp")

add_executable(extracter ${SRCS})

# 查找 DWARF 库
find_library(DWARF_LIB NAMES dwarf)

if(DWARF_LIB)
    target_link_libraries(extracter ${DWARF_LIB})
else()
    message(WARNING "DWARF library not found.")
endif()
