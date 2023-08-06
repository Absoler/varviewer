#!/usr/local/bin/python3

import sys, os, re

# usually `./random`
testPath = sys.argv[1]
# number of already prepared files
testCount = int(sys.argv[2])
# output file of test results
testOutputPath = sys.argv[3]

gdbScriptContent = ""
gdbTempScriptPath = "gdb.x"
resultRe = re.compile(r'correct (?P<correct>\d+) / (?P<wrong>\d+)')
sumCorrect, sumWrong = 0, 0

for i in range(testCount):
    testFileName = f"{testPath}/random_{i}"
    if os.system(testFileName) != 0:
        continue
    if os.system(f"../extracter/extracter {testFileName} -o {testFileName}.var") != 0:
        continue
    if os.system(f"../analysis/main.py {testFileName} {testFileName}.var -tP /tmp/random -o {testFileName}.match") != 0:
        continue
    gdbScriptContent = f'''set pagination off
source gdbCheck.py
check_variables {testFileName}.match {testOutputPath}
quit
y'''
    with open(gdbTempScriptPath, "w") as gdbTempScript:
        gdbTempScript.write(gdbScriptContent)
    os.system(f"gdb {testFileName} -x {gdbTempScriptPath}")

resultFile = open(testOutputPath, "r")
for line in resultFile.readlines():
    line = line.strip()
    if not line:
        continue
    matchObj = resultRe.match(line)
    correct, wrong = int(matchObj.group('correct')), int(matchObj.group('wrong'))
    sumCorrect += correct
    sumWrong += wrong

outputInfo = f'''test {testCount} files in total\n
match {sumCorrect} successfully of {sumCorrect+sumWrong}'''