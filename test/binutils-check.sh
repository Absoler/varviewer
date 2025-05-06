#!/bin/bash

# 定义基础路径（根据您的实际环境调整）
BASE_DIR="/root/varviewer/test"
BINUTILS_DIR="/root/fuzzing_binutils"
DATASET_BIN="../dataset-optimizer/bin"

# 启动 objdump 测试
tmux new-session -d -s objdump-gdb \
  "python3 $BASE_DIR/batch.py \
  $BASE_DIR/binutils-o2/objdump/objdump-o2_result.json \
  $DATASET_BIN/objdump \
  $BINUTILS_DIR/fuzzing_objdump/out/default/queue/ \
  $BASE_DIR/temp2/ \
  dxsrtTprS"

# 启动 readelf 测试
tmux new-session -d -s readelf-gdb \
  "python3 $BASE_DIR/batch.py \
  $BASE_DIR/binutils-o2/readelf/readelf-o2_result.json \
  $DATASET_BIN/readelf \
  $BINUTILS_DIR/fuzzing_objdump/out/default/queue/ \
  $BASE_DIR/temp/ \
  a"

# 启动 strip 测试
tmux new-session -d -s strip-gdb \
  "python3 $BASE_DIR/batch.py \
  $BASE_DIR/binutils-o2/strip/strip-o2_result.json \
  $DATASET_BIN/strip \
  $BINUTILS_DIR/fuzzing_strip/out/default/queue/ \
  $BASE_DIR/temp3/"

# 启动 nm 测试
tmux new-session -d -s nm-gdb \
  "python3 $BASE_DIR/batch.py \
  $BASE_DIR/binutils-o2/nm/nm-o2_result.json \
  $DATASET_BIN/nm \
  $BINUTILS_DIR/fuzzing_nm/out/default/queue/ \
  $BASE_DIR/temp4/"

# 显示所有启动的会话
echo "已启动以下 tmux 会话："
echo "1. objdump-gdb"
echo "2. readelf-gdb"
echo "3. strip-gdb"
echo "4. nm-gdb"

echo -e "\n使用以下命令查看运行状态："
echo "tmux attach -t [会话名]"
echo "或列出所有会话：tmux ls"