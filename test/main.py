#!/usr/local/bin/python3

import sys, os, re
import json
from util import VariableType

# usually `./random`
testPath = sys.argv[1]
# number of already prepared files
testCount = int(sys.argv[2])
# startIndex of test cases
startInd = int(sys.argv[3]) if len(sys.argv) > 3 else 0

gdbScriptContent = ""
gdbTempScriptPath = "gdb.x"
resultRe = re.compile(r'correct (?P<correct>\d+) / (?P<all>\d+)')
sumCorrect, sumAll = 0, 0
resultJson = { key.name : [0, 0] for key in VariableType}


for i in range(startInd, testCount):
    testFileName = f"{testPath}/random_{i}"
    if os.system(f"timeout 3s {testFileName}") != 0:
        continue
    if os.system(f"../extracter/extracter {testFileName} -o {testFileName}.var > /dev/null 2>&1") != 0:
        continue
    if os.system(f"../analysis/main.py {testFileName} {testFileName}.var -tP /tmp/random -o {testFileName}.match > /dev/null") != 0:
        continue
    gdbScriptContent = f'''set pagination off
source gdbCheck.py
check_variables {testFileName}.match {testFileName}.count
quit
y'''
    with open(gdbTempScriptPath, "w") as gdbTempScript:
        gdbTempScript.write(gdbScriptContent)
    os.system(f"gdb {testFileName} -x {gdbTempScriptPath}")

    with open(f"{testFileName}.count", "r") as countFile:
        countJson = json.load(countFile)
        for key in VariableType:
            resultJson[key.name][0] += countJson[key.name][0]
            resultJson[key.name][1] += countJson[key.name][1]


print(json.dumps(resultJson, indent=4))
# for line in resultFile.readlines():
#     line = line.strip()
#     if not line:
#         continue
#     matchObj = resultRe.search(line)
#     if not matchObj:
#         continue
#     correct, all = int(matchObj.group('correct')), int(matchObj.group('all'))
#     sumCorrect += correct
#     sumAll += all

# outputInfo = f'''test {testCount} files in total
# match {sumCorrect} successfully of {sumAll}'''

# print(outputInfo)