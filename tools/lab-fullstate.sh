#!/usr/bin/env bash
# lab-fullstate.sh —— 全链终态自检夹具
#
# 作用：在临时目录里重建一份「child.malware / ninel / pam_master 家族
#       完全感染后」的终态，然后验证 rkk 的检出与清除是否都成立。
#
# 为什么用合成终态：真实 payload 在 C2 上，取回并执行它正是我们要防的事。
# 但检测与清除的对象是「痕迹」，不是 payload，所以合成终态足以验证工具。
#
# 安全：全部操作都在 mktemp 出来的临时根目录内（通过 RKK_ROOT 限定），
#       不触碰真实的 /etc、/root、/usr。
#
# 用法：
#   ./tools/lab-fullstate.sh                  # 自动找 dist/rkk-linux-amd64
#   ./tools/lab-fullstate.sh /path/to/rkk     # 指定二进制
#   KEEP=1 ./tools/lab-fullstate.sh           # 跑完保留现场
#
set -u

cd "$(dirname "$0")/.." || exit 1
ROOT_DIR=$(pwd)

if [ $# -ge 1 ]; then
  RKK="$1"
elif [ -x "$ROOT_DIR/dist/rkk-linux-amd64" ]; then
  RKK="$ROOT_DIR/dist/rkk-linux-amd64"
else
  echo "找不到 rkk 二进制，请先 make 或显式传入路径" >&2
  exit 1
fi

case "$RKK" in
  /*) ;;
  *) RKK="$ROOT_DIR/$RKK" ;;
esac
[ -x "$RKK" ] || { echo "不可执行：$RKK" >&2; exit 1; }

SB=$(mktemp -d "${TMPDIR:-/tmp}/rkk-fullstate.XXXXXX")
FAIL=0
ok()   { printf '  [OK]   %s\n' "$1"; }
bad()  { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }

cleanup() { [ "${KEEP:-0}" = "1" ] || rm -rf "$SB"; }
trap cleanup EXIT

echo "== 沙盒：$SB"
echo "== 二进制：$RKK"
echo ""

# ---------------------------------------------------------------- 1. 造终态
echo "[1/4] 构造全链终态"
mkdir -p "$SB"/etc/pam.d "$SB"/etc/cron.d "$SB"/etc/systemd/system \
         "$SB"/usr/lib "$SB"/usr/local/lib "$SB"/usr/bin \
         "$SB"/var/tmp/.ladyg0g0 "$SB"/root/.ssh \
         "$SB"/dev/shm "$SB"/opt "$SB"/usr/local/share "$SB"/usr/local/bin \
         "$SB"/var/log

printf '/usr/lib/libnss_ninel.so.2\n'                        > "$SB/etc/ld.so.preload"
printf 'passwd: files ninel\ngroup: files ninel\nshadow: files ninel\nhosts: files dns\n' \
                                                            > "$SB/etc/nsswitch.conf"
printf 'auth required pam_master.so\naccount required pam_master.so\n' \
                                                            > "$SB/etc/pam.d/common-auth"
: > "$SB/usr/lib/libnss_ninel.so.2"                          # 0 字节占位
printf '#!/bin/sh\nexec /bin/sh\n'  > "$SB/usr/bin/ssshd"     && chmod 755 "$SB/usr/bin/ssshd"
echo x                              > "$SB/var/tmp/.ladyg0g0/.pr1nc35"
printf '[Unit]\nDescription=svc\n[Service]\nExecStart=/usr/bin/ssshd\n[Install]\nWantedBy=multi-user.target\n' \
                                    > "$SB/etc/systemd/system/myservices.service"
printf 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB attacker@ElPatrono1337\n' \
                                    > "$SB/root/.ssh/authorized_keys"
printf 'root:x:0:0::/root:/bin/bash\nninel:x:0:1::/:/bin/sh\n' \
                                    > "$SB/etc/passwd"
echo '# cron'                       > "$SB/etc/cron.d/systemd-timers.hider.89"
echo x                              > "$SB/dev/shm/.X-systemd.hider.89"
echo x                              > "$SB/var/log/.apt-cache.log"
echo x                              > "$SB/usr/local/bin/systemd-resolved-helper"
echo ok

# ---------------------------------------------------------------- 2. 检出
echo "[2/4] 检出（期望全部命中）"
SCAN_OUT=$(RKK_ROOT="$SB" "$RKK" scan 2>&1)
echo "$SCAN_OUT" | sed -n '1,3p'
HITS=$(echo "$SCAN_OUT" | grep -c '\[[A-Z ]*\]')
if [ "$HITS" -ge 13 ]; then ok "命中 $HITS 项（≥13）"; else bad "只命中 $HITS 项，低于预期 13"; fi

for kw in 'ld.so.preload' 'nsswitch.conf' 'pam.d/common-auth' 'ssshd' 'myservices.service' \
          'authorized_keys' 'libnss_ninel.so.2' 'ninel'; do
  if echo "$SCAN_OUT" | grep -q "$kw"; then ok "报出 $kw"; else bad "漏报 $kw"; fi
done

# ---------------------------------------------------------------- 3. 清除
echo ""
echo "[3/4] 清除"
RKK_ROOT="$SB" "$RKK" clean -yes 2>&1 | tail -4
echo ""

# ---------------------------------------------------------------- 4. 逐项核对
echo "[4/4] 清除后逐项核对"
check_gone() { if [ -e "$SB/$1" ]; then bad "$1 仍存在"; else ok "$1 已移除"; fi; }

check_gone etc/ld.so.preload
check_gone usr/bin/ssshd
check_gone etc/systemd/system/myservices.service
check_gone usr/lib/libnss_ninel.so.2
check_gone var/tmp/.ladyg0g0/.pr1nc35
check_gone etc/cron.d/systemd-timers.hider.89
check_gone dev/shm/.X-systemd.hider.89

# 配置文件必须是「精准修复」，不能整文件删掉
if [ -f "$SB/etc/nsswitch.conf" ] && ! grep -q ninel "$SB/etc/nsswitch.conf"; then
  ok "nsswitch.conf 已去除 ninel"
  grep -q 'hosts: files dns' "$SB/etc/nsswitch.conf" \
    && ok "nsswitch.conf 保留 hosts 行（未误删）" \
    || bad "nsswitch.conf 丢失 hosts 行（误删）"
else
  bad "nsswitch.conf 仍含 ninel 或文件丢失"
fi

if ! grep -q pam_master "$SB/etc/pam.d/common-auth" 2>/dev/null; then
  ok "pam.d/common-auth 已去除 pam_master"
else
  bad "pam.d/common-auth 仍含 pam_master"
fi

if ! grep -q '^ninel:' "$SB/etc/passwd" 2>/dev/null; then
  ok "后门账户 ninel 已删除"
else
  bad "后门账户 ninel 仍存在"
fi

if ! grep -q 'ElPatrono' "$SB/root/.ssh/authorized_keys" 2>/dev/null; then
  ok "攻击者公钥已删除"
else
  bad "攻击者公钥仍在 authorized_keys"
fi

RESCAN=$(RKK_ROOT="$SB" "$RKK" scan 2>&1)
if echo "$RESCAN" | grep -q '未发现匹配特征'; then
  ok "复检清零"
else
  bad "复检仍有残留：$(echo "$RESCAN" | grep -c '\[[A-Z ]*\]') 项"
fi

BK=$(find "$SB/var/backups" -maxdepth 1 -type d -name 'rootkit-killer-*' 2>/dev/null | head -1)
if [ -n "$BK" ]; then ok "已生成备份：$(basename "$BK")"; else bad "没有生成备份目录"; fi

echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "RESULT: PASS（全链终态检出 + 清除 全部通过）"
  exit 0
else
  echo "RESULT: FAIL（$FAIL 项未通过）"
  [ "${KEEP:-0}" = "1" ] && echo "现场保留在：$SB"
  exit 1
fi
