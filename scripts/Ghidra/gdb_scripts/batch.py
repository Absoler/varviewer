import sys
import os
import re

def main():
    for file in os.listdir(os.getcwd()):
        if file.endswith(".c"):
            testcase = re.sub(r"\.c$", "", file)
            print(f"testcase: {testcase}")
            elf_path = testcase + ".o"

            input_json_mem = testcase + ".mem.json"
            output_json_mem = testcase + ".mem.result.json"

            input_json_reg = testcase + ".reg.json"
            output_json_reg = testcase + ".reg.result.json"

            gdb_script = (
                "source varchk.py\n"
                f"varchk {input_json_mem} {output_json_mem}\n"
                f"varchk {input_json_reg} {output_json_reg}\n"
                "quit\n"
                "y\n"
            )
            with open("/tmp/gdb.x", "w") as gdbx:
                gdbx.write(gdb_script)
            print(f"testing with gdb...")
            os.system(f"gdb {elf_path} -x /tmp/gdb.x -q")


if __name__ == "__main__":
    main()
