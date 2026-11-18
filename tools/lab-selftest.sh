#!/bin/sh
# rkk 自测包：在真实主机上验证「检测 → 清除 → 复检」全流程，
# 但不使用真样本。用的是与木马落点完全一致的仿真目录树。
#
# 用法（在工程根目录）：
#   sh tools/lab-selftest.sh
#   sh tools/lab-selftest.sh ./dist/rkk-linux-arm64 /tmp/rkk-lab
set -eu

BIN=${1:-./dist/rkk-linux-amd64}
LAB=${2:-/tmp/rkk-lab}

if [ ! -x "$BIN" ]; then
  echo "找不到可执行文件：$BIN" >&2
  exit 1
fi

echo "============================================================"
echo " rkk 自测  二进制=$BIN  仿真根=$LAB"
echo " 这台机不会被改动：清除动作全部限定在 $LAB 内（RKK_ROOT）"
echo "============================================================"

echo
echo "[1/4] 先看这台机当前状态（只读）"
"$BIN" scan || true

echo
echo "[2/4] 生成仿真感染（与木马落点一一对应的占位文件，不是真样本）"
sh "$(dirname "$0")/make-test-fixture.sh" "$LAB"
echo "   落点数量：$(find "$LAB" -type f | wc -l) 个文件"

echo
echo "[3/4] 对仿真环境扫描（预期：命中多项）"
OUT=/tmp/rkk-lab-scan.txt
RKK_ROOT="$LAB" "$BIN" scan >"$OUT" 2>&1 || true
HITS=$(grep -cE '^\s*[0-9]+\. \[' "$OUT" || true)
echo "   命中 $HITS 项，明细见 $OUT"
if [ "$HITS" -lt 5 ]; then
  echo "   [FAIL] 命中过少，检测规则可能失效" >&2
  exit 1
fi

echo
echo "[4/4] 对仿真环境执行清除，然后复检"
RKK_ROOT="$LAB" "$BIN" clean -yes -aggressive || true
RKK_ROOT="$LAB" "$BIN" scan >/tmp/rkk-lab-rescan.txt 2>&1 || true
LEFT=$(grep -cE '^\s*[0-9]+\. \[' /tmp/rkk-lab-rescan.txt || true)
echo "   清除后残留：$LEFT 项（明细见 /tmp/rkk-lab-rescan.txt）"

echo
if [ "$LEFT" -eq 0 ]; then
  echo "结果：PASS —— 检测与清除闭环正常"
else
  echo "结果：FAIL —— 仍有残留，请把 /tmp/rkk-lab-rescan.txt 发回来" >&2
  exit 1
fi
echo
echo "下一步（确认无误后再做，会改动本机）："
echo "  $BIN install -yes       # 布防 + 常驻巡检 + 自动清除"
echo "  $BIN status             # 查看布防点与最近动作"
