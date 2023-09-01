#!/usr/local/bin/python3

import sys, os, re

# usually `./random`
testPath = sys.argv[1]
# number of already prepared files
testCount = int(sys.argv[2])
# output file of test results
testOutputPath = sys.argv[3]
# startIndex of test cases
startInd = int(sys.argv[4]) if len(sys.argv) > 4 else 0

gdbScriptContent = ""
gdbTempScriptPath = "gdb.x"
resultRe = re.compile(r'correct (?P<correct>\d+) / (?P<all>\d+)')
sumCorrect, sumAll = 0, 0

for i in range(startInd, testCount):
    testFileName = f"{testPath}/random_{i}"
    if os.system(testFileName) != 0:
        continue
    if os.system(f"../extracter/extracter {testFileName} -o {testFileName}.var > /dev/null 2>&1") != 0:
        continue
    if os.system(f"../analysis/main.py {testFileName} {testFileName}.var -tP /tmp/random -o {testFileName}.match > /dev/null") != 0:
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
    matchObj = resultRe.search(line)
    if not matchObj:
        continue
    correct, all = int(matchObj.group('correct')), int(matchObj.group('all'))
    sumCorrect += correct
    sumAll += all

outputInfo = f'''test {testCount} files in total
match {sumCorrect} successfully of {sumAll}'''

print(outputInfo)