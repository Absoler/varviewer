#!/usr/local/bin/python3
import os, sys

''' generate random C source files with csmith

    argv[1]: number of generated files
    argv[2]: output directory
    argv[3]: root directory of csmith
'''

options:str = ' '.join([
    "--no-safe-math",
    "--no-checksum"
])

compiler = "gcc-12.1"
compiler_options:str = "-gdwarf-4 -O2"

genCount = int(sys.argv[1])
outputDir = os.path.normpath(sys.argv[2])
csmith_root = os.path.normpath(sys.argv[3])
csmith = f"{csmith_root}/src/csmith"
csmith_include = f"{csmith_root}/runtime"

if not os.path.exists(outputDir):
    os.mkdir(outputDir)

for i in range(genCount):
    random_i_name:str = f"{outputDir}/random_{i}"
    os.system(f"{csmith} {options} -o {random_i_name}.c")
    os.system(f"{compiler} {random_i_name}.c {compiler_options} -I {csmith_include} -o {random_i_name}")