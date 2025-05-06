import argparse
import subprocess
from pathlib import Path
import json

def run_gdb_tests(args):
    input_dir = Path(args.input_path)
    output_dir = Path(args.output_path)
    result_file = Path(args.result_file)

    if args.option != "-":
        option = '-' + args.option
    else:
        option = ""

    input_files = sorted(f for f in input_dir.glob("*") if not f.name.startswith("."))
    output_dir.mkdir(parents=True, exist_ok=True)

    # 仅记录累加值
    total_stats = {
        "INVALID": [0, 0],
        "MEM_CFA": [0, 0],
        "MEM_SINGLE": [0, 0],
        "MEM_MULTI": [0, 0],
        "REG_PARAM": [0, 0],
        "REG_OTHER": [0, 0],
        "IMPLICIT": [0, 0]
    }

    file_count = 0

    for input_file in input_files:
        output_file = output_dir / (input_file.name + ".json")

        gdb_cmd = [
            "gdb", "-x", "./gdbCheck.py", "-q",
            "-ex", "set pagination off",
            args.test_target,
            "-ex", f"check_variables {result_file} {output_file} {input_file} {option}"
        ]
        print(f"Running: {' '.join(gdb_cmd)}")

        try:
            subprocess.run(gdb_cmd, check=True)
            with open(output_file, "r") as f:
                data = json.load(f)
            
            for var_type, (hit, total) in data.items():
                total_stats[var_type][0] += hit
                total_stats[var_type][1] += total
            
            file_count += 1
            output_file.unlink()
        except Exception as e:
            print(f"Error processing {input_file}: {e}")

    # 计算平均值（直接使用累加值）
    final_stats = {
        var_type: [
            round(hit / file_count) if file_count > 0 else 0,
            round(total / file_count) if file_count > 0 else 0
        ]
        for var_type, (hit, total) in total_stats.items()
    }

    # 保存结果（保持原始JSON结构）
    summary_file = output_dir / f"{Path(args.test_target).name}_summary.json"
    with open(summary_file, "w") as f:
        json.dump(final_stats, f, indent=4)
    print(f"Final summary saved to {summary_file}")

def main():
    parser = argparse.ArgumentParser(description="Batch process test cases.")
    parser.add_argument("result_file", type=str, help="the result file.")
    parser.add_argument("test_target", type=str, help="the test target.")      
    parser.add_argument("input_path", type=str, help="the input path.")           
    parser.add_argument("output_path", type=str, help="the output path.")        
    parser.add_argument("option", type=str, nargs="?", default="", help="the option.")                
    args = parser.parse_args()
    run_gdb_tests(args)

if __name__ == "__main__":
    main()