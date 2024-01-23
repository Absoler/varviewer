# correctness test
To guarantee functional equivalence of analysis module during development, basic and quick test tool is a need.
7 different kinds of dwarf expressions are taken into consideration, and we need test them on a built linux kernel, whose build option is as follows:
1. linux kernel version rc6.0.0
2. default config
3. open debug info and switch dwarf version to 4 in `.config` by hand
4. use gcc-12.1.0, and specify CC and HOSTCC