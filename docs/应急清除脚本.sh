#!/bin/bash
# =============================================================================
# 应急清除脚本 —— 针对 ***.*** 上的 Linux rootkit（child.malware 家族）
#
# 用法：
#   bash 应急清除脚本.sh            # 演练模式（只打印将要做什么，不改动任何东西）
#   bash 应急清除脚本.sh --apply    # 真正执行（自动备份到 /root/ir-<时间戳>/）
#
# 重要：
#   1) 必须 root 执行；
#   2) 执行前先断掉 C2 出站（***.*** / digital.digitaldatainsights.org），
#      否则清理过程中可能被下发新版本；
#   3) 本脚本第 1 步就会移除 /etc/ld.so.preload。执行完后请【新开一个会话】再继续
#      后续手工核对，因为当前这个 shell 很可能已经带着隐藏库在运行；
#   4) 被替换的 /usr/bin/{rm,kill,chattr,passwd} 不要用 /dev/shm/.orig_* 恢复，
#      那是木马的一部分，脚本会重装 coreutils 并把这些 .orig_* 也归档掉；
#   5) root + PAM 后门 + initramfs 持久化 => 信任链已断。清理只是止血，
#      最终仍建议换机重建，只迁回数据文件。
# =============================================================================
set -uo pipefail

APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

TS="$(date +%Y%m%d-%H%M%S)"
EVID="/root/ir-$TS"
HAD_ERR=0

c_red=$'\033[31m'; c_yel=$'\033[33m'; c_grn=$'\033[32m'; c_dim=$'\033[2m'; c_rst=$'\033[0m'

say()  { printf '%s\n' "$*"; }
step() { printf '\n%s== %s ==%s\n' "$c_yel" "$*" "$c_rst"; }
ok()   { printf '%s  [OK] %s%s\n' "$c_grn" "$*" "$c_rst"; }
warn() { printf '%s  [!!] %s%s\n' "$c_yel" "$*" "$c_rst"; }
err()  { printf '%s  [XX] %s%s\n' "$c_red" "$*" "$c_rst"; HAD_ERR=1; }

# 执行（演练模式只打印）
run() {
  if [ "$APPLY" -eq 1 ]; then
    eval "$@"
    local rc=$?
    [ $rc -ne 0 ] && warn "命令返回非 0（$rc）：$*"
    return 0
  fi
  printf '%s  $ %s%s\n' "$c_dim" "$*" "$c_rst"
}

# 把文件/目录移进取证目录（不直接删除，可回滚）
quarantine() {
  local p="$1"
  [ -e "$p" ] || [ -L "$p" ] || return 0
  local rel
  rel="$(printf '%s' "$p" | sed 's#^/##; s#/#_#g')"
  if [ "$APPLY" -eq 1 ]; then
    mkdir -p "$EVID/files"
    mv -f "$p" "$EVID/files/$rel" 2>/dev/null && ok "已隔离 $p" || err "隔离失败 $p"
  else
    printf '%s  $ mv %s -> %s/files/%s%s\n' "$c_dim" "$p" "$EVID" "$rel" "$c_rst"
  fi
}

# 备份单个文件（保留原路径信息）
backup_one() {
  local p="$1"
  [ -e "$p" ] || return 0
  local rel
  rel="$(printf '%s' "$p" | sed 's#^/##; s#/#_#g')"
  if [ "$APPLY" -eq 1 ]; then
    mkdir -p "$EVID/backup"
    cp -a "$p" "$EVID/backup/$rel" 2>/dev/null
  else
    printf '%s  $ cp -a %s -> %s/backup/%s%s\n' "$c_dim" "$p" "$EVID" "$rel" "$c_rst"
  fi
}

# ---------------------------------------------------------------- 前置检查
step "前置检查"
if [ "$APPLY" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
  err "必须以 root 执行（当前 uid=$(id -u)）"; exit 1
fi
say "模式：$([ "$APPLY" -eq 1 ] && echo '【执行】' || echo '【演练，不做任何改动】')"
say "取证目录：$EVID"
case "$(cat /etc/os-release 2>/dev/null | tr -d '"')" in
  *debian*|*ubuntu*) DISTRO=debian ;;
  *rhel*|*centos*|*fedora*|*rocky*|*alma*) DISTRO=rhel ;;
  *) DISTRO=other ;;
esac
say "发行版判定：$DISTRO"

if [ "$APPLY" -eq 1 ]; then
  mkdir -p "$EVID/files" "$EVID/backup"
  {
    echo "=== 采集时间 $TS ==="
    echo "--- ld.so.preload"; cat /etc/ld.so.preload 2>/dev/null
    echo "--- nsswitch.conf"; grep -E '^(passwd|shadow|group)' /etc/nsswitch.conf 2>/dev/null
    echo "--- passwd ninel/node"; grep -E '^(ninel|node):' /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null
    echo "--- sudoers.d"; ls -l /etc/sudoers.d/ 2>/dev/null
    echo "--- cron.d"; ls -l /etc/cron.d/ 2>/dev/null
    echo "--- root crontab"; crontab -l -u root 2>/dev/null
    echo "--- sshd_config 关键行"; grep -nE 'Match User|AuthorizedKeysFile|StrictModes|PermitRootLogin|Port ' /etc/ssh/sshd_config 2>/dev/null
    echo "--- authorized_keys"; cat /root/.ssh/authorized_keys 2>/dev/null
    echo "--- pam_master 引用"; grep -rn 'pam_master' /etc/pam.d/ 2>/dev/null
    echo "--- .pm"; cat /etc/.pm 2>/dev/null
    echo "--- systemd 可疑 unit"; ls -l /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null | grep -Ei 'systemd-(resolved-cache|networkd-helper|timesyncd-update|journald-cache)|dbus-system-helper|myservices|update-checker'
    echo "--- initramfs hooks"; ls -l /etc/initramfs-tools/hooks/ /usr/share/initramfs-tools/hooks/ 2>/dev/null
    echo "--- 可疑目录"; ls -la /dev/shm/ /var/tmp/ /usr/local/lib/ 2>/dev/null
  } > "$EVID/prescan.txt" 2>&1
  ok "已保存现场快照：$EVID/prescan.txt"
fi

# ------------------------------------------------- 1. 关闭全局 preload（总开关）
step "1/11 关闭 LD_PRELOAD 总开关（/etc/ld.so.preload）"
if [ -e /etc/ld.so.preload ]; then
  backup_one /etc/ld.so.preload
  warn "/etc/ld.so.preload 存在，内容："; sed 's/^/       /' /etc/ld.so.preload 2>/dev/null
  quarantine /etc/ld.so.preload
  run "ldconfig 2>/dev/null || true"
  warn "完成后请新开一个 SSH/控制台会话再继续核对（当前 shell 可能仍带着 hook）"
else
  ok "/etc/ld.so.preload 不存在"
fi

# ------------------------------------------------- 2. 修复 nsswitch.conf
step "2/11 修复 /etc/nsswitch.conf（去掉 ninel）"
if grep -q 'ninel' /etc/nsswitch.conf 2>/dev/null; then
  backup_one /etc/nsswitch.conf
  run "sed -i -E 's/\\bninel\\b//g; s/[[:space:]]+/ /g; s/ (files|dns|compat|myhostname|resolve|systemd|nis|ldap|winbind|mymachines)\\b/ \\1/g' /etc/nsswitch.conf"
  run "sed -i -E 's/^(passwd|shadow|group):[[:space:]]+:/\\1: /' /etc/nsswitch.conf"
  run "sed -i -E 's/[[:space:]]+$//' /etc/nsswitch.conf"
  ok "已清理 nsswitch.conf（建议手工确认 passwd/shadow/group 三行为 files 或 files dns）"
else
  ok "nsswitch.conf 中无 ninel"
fi

# ------------------------------------------------- 3. 摘除 PAM 后门
step "3/11 摘除 PAM 后门（pam_master.so）"
PAM_MODS="/lib/security/pam_master.so
/lib64/security/pam_master.so
/lib/x86_64-linux-gnu/security/pam_master.so
/lib/aarch64-linux-gnu/security/pam_master.so
/usr/lib64/security/pam_master.so
/usr/lib/security/pam_master.so"
echo "$PAM_MODS" | while read -r m; do
  [ -n "$m" ] || continue
  if [ -e "$m" ]; then
    backup_one "$m"; quarantine "$m"
  fi
done

# 优先用 .pm-bak 还原，否则按行删除
for f in /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-session /etc/pam.d/password-auth /etc/pam.d/system-auth; do
  [ -e "$f" ] || continue
  grep -q 'pam_master' "$f" 2>/dev/null || continue
  backup_one "$f"
  if [ -e "$f.pm-bak" ]; then
    run "cp -a '$f.pm-bak' '$f'"
    ok "从 $f.pm-bak 还原"
  else
    run "sed -i '/pam_master/d' '$f'"
    ok "已从 $f 删除 pam_master 行"
  fi
done
# 残留备份文件一并归档
for f in /etc/pam.d/*.pm-bak /etc/pam.d/*.pam-bak /etc/pam.d/*.pam-old; do
  [ -e "$f" ] || continue; quarantine "$f"
done
quarantine /etc/.pm

if [ "$DISTRO" = "debian" ] && command -v pam-auth-update >/dev/null 2>&1; then
  run "DEBIAN_FRONTEND=noninteractive pam-auth-update --force </dev/null >/dev/null 2>&1 || true"
fi
if [ "$DISTRO" = "rhel" ] && [ -d /etc/authselect/custom/pam_master ]; then
  run "authselect select $(grep -oP '^current\s+\K.*' /etc/authselect/authselect.conf 2>/dev/null || echo sssd) --force </dev/null >/dev/null 2>&1 || true"
  quarantine /etc/authselect/custom/pam_master
fi
warn "请务必另开一个控制台测试登录，确认 PAM 栈正常（不要只留一个 SSH 窗口）"

# ------------------------------------------------- 4. 恢复被替换的系统命令
step "4/11 重装被木马替换的命令（rm/kill/chattr/passwd/chpasswd）"
SUSPECT_BINS="/usr/bin/rm /usr/bin/kill /usr/bin/chattr /usr/bin/passwd /usr/bin/chpasswd /usr/sbin/kill /usr/sbin/chattr"
for b in $SUSPECT_BINS; do
  [ -e "$b" ] || continue
  if head -c 200 "$b" 2>/dev/null | grep -qa 'UPX!' ; then
    warn "$b 带 UPX 壳（木马特征）"
  fi
done
if [ "$DISTRO" = "debian" ]; then
  run "apt-get install --reinstall -y coreutils passwd util-linux </dev/null"
elif [ "$DISTRO" = "rhel" ]; then
  run "yum reinstall -y coreutils shadow-utils util-linux </dev/null || dnf reinstall -y coreutils shadow-utils util-linux </dev/null"
else
  err "未知发行版，请手工从可信介质恢复 coreutils/passwd/util-linux"
fi
for b in /usr/libexec/.rm /usr/libexec/.kill /usr/libexec/.chatattr /usr/libexec/.apt /usr/libexec/.apt-cli /usr/bin/ssshd; do
  [ -e "$b" ] && { backup_one "$b"; quarantine "$b"; }
done
warn "不要用 /dev/shm/.orig_rm 等文件恢复命令——它们本身就是木马组件"

# ------------------------------------------------- 5. 清理 SSH 后门
step "5/11 清理 SSH 公钥后门与 sshd_config"
ATTACKER_FP="SHA256:AkrAM6Cdbkqok1OHU527WzpYGQqPQJrubcEP9Dlj7yI"
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys /var/tmp/updates-20260202; do
  [ -e "$f" ] || continue
  backup_one "$f"
  if [ "$APPLY" -eq 1 ]; then
    cp -a "$f" "$f.bak-$TS" 2>/dev/null
    awk -v fp="$ATTACKER_FP" '
      /^[[:space:]]*[#]/{print;next}
      {
        tmp="/tmp/.akcheck"; print > tmp; close(tmp)
        cmd="ssh-keygen -lf " tmp " 2>/dev/null";
        if ((cmd | getline line) > 0) {
          close(cmd)
          if (line ~ fp || $0 ~ "ElPatrono1337") { next }
        } else { close(cmd) }
        print
      }' "$f" > "$f.cleaned" 2>/dev/null
    if [ -s "$f.cleaned" ] || [ ! -s "$f" ]; then
      cat "$f.cleaned" > "$f"; ok "已从 $f 移除攻击者公钥"
    else
      warn "$f 清理结果为空，请手工核对后再决定（原文件已备份为 $f.bak-$TS）"
    fi
    rm -f "$f.cleaned" /tmp/.akcheck
  else
    printf '%s  $ 从 %s 中删除指纹 %s / 注释 ElPatrono1337 的行%s\n' "$c_dim" "$f" "$ATTACKER_FP" "$c_rst"
  fi
done
[ -e /var/tmp/updates-20260202 ] && { backup_one /var/tmp/updates-20260202; quarantine /var/tmp/updates-20260202; }

if grep -qE 'Match User ninel|updates-20260202|StrictModes no' /etc/ssh/sshd_config 2>/dev/null; then
  backup_one /etc/ssh/sshd_config
  if [ -e /etc/ssh/sshd_config.pm-bak ]; then
    run "cp -a /etc/ssh/sshd_config.pm-bak /etc/ssh/sshd_config"; ok "已从 sshd_config.pm-bak 还原"
  elif [ "$APPLY" -eq 1 ]; then
    # 删除 "# OpenSSH server - user access rules" 起的 Match 块（到下一个顶格行为止）
    awk '
      /^# OpenSSH server - user access rules/ {skip=1; next}
      skip==1 && /^[[:space:]]/ {next}
      skip==1 && /^Match / {next}
      skip==1 {skip=0}
      {print}' /etc/ssh/sshd_config > /etc/ssh/sshd_config.cleaned
    cat /etc/ssh/sshd_config.cleaned > /etc/ssh/sshd_config
    rm -f /etc/ssh/sshd_config.cleaned
    sed -i -E '/^[[:space:]]*StrictModes[[:space:]]+no[[:space:]]*$/d' /etc/ssh/sshd_config
    ok "已移除 sshd_config 中的 Match User ninel 块与 StrictModes no"
  else
    printf '%s  $ 移除 sshd_config 中 Match User ninel 块 / StrictModes no 行%s\n' "$c_dim" "$c_rst"
  fi
  run "sshd -t </dev/null && (systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null) || true"
else
  ok "sshd_config 未见后门配置"
fi

# ------------------------------------------------- 6. 清理后门账户与 sudoers
step "6/11 清理账户与 sudoers"
for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do
  grep -qE '^ninel:' "$f" 2>/dev/null || continue
  backup_one "$f"
  run "sed -i -E '/^ninel:/d' '$f'"
  ok "已从 $f 删除 ninel 账户记录"
done
grep -qE '^node:' /etc/passwd 2>/dev/null && warn "/etc/passwd 仍存在 node 账户，请人工确认是否业务账号，再决定是否删除"
for f in /etc/sudoers.d/99-ninel-root /etc/sudoers.d/node /etc/sudoers.d/.99-ninel-root; do
  [ -e "$f" ] && { backup_one "$f"; quarantine "$f"; }
done
run "visudo -c </dev/null >/dev/null 2>&1 || true"

# ------------------------------------------------- 7. 清理持久化
step "7/11 清理 cron / systemd / rc.local / shell 启动项"
for f in /etc/cron.d/systemd-timers /etc/cron.d/systemd-boot /etc/cron.d/systemd-boot-early \
         /etc/cron.d/.systemd-update-notifier /etc/cron.d/systemd-boot-early; do
  [ -e "$f" ] && { backup_one "$f"; quarantine "$f"; }
done
if crontab -l -u root 2>/dev/null | grep -qE 'system-service|876c7af6|01b51ec6'; then
  if [ "$APPLY" -eq 1 ]; then
    crontab -l -u root 2>/dev/null > "$EVID/backup/root.crontab"
    crontab -l -u root 2>/dev/null | grep -vE 'system-service|876c7af6|01b51ec6' | crontab -u root - 2>/dev/null
    ok "已清理 root crontab"
  else
    printf '%s  $ 清理 root crontab 中 system-service / 876c7af6 相关行%s\n' "$c_dim" "$c_rst"
  fi
fi

UNITS="systemd-resolved-cache systemd-networkd-helper systemd-timesyncd-update dbus-system-helper systemd-journald-cache myservices service-manager daemon-helper system-monitor service-controller update-daemon background-service"
for u in $UNITS; do
  run "systemctl disable --now $u.service </dev/null >/dev/null 2>&1 || true"
done
for p in /etc/systemd/system/systemd-resolved-cache.service \
         /etc/systemd/system/systemd-networkd-helper.service \
         /etc/systemd/system/systemd-timesyncd-update.service \
         /etc/systemd/system/dbus-system-helper.service \
         /etc/systemd/system/systemd-journald-cache.service \
         /etc/systemd/system/myservices.service \
         /usr/lib/systemd/system/myservices.service \
         /etc/systemd/system/multi-user.target.wants/myservices.service \
         /etc/systemd/system-generators/system-service-generator \
         /etc/systemd/system-generators/update-checker \
         /usr/local/lib/systemd/system-generators/update-checker \
         /usr/local/lib/systemd/system-generators/system-service-generator ; do
  [ -e "$p" ] && { backup_one "$p"; quarantine "$p"; }
done
run "systemctl daemon-reload </dev/null >/dev/null 2>&1 || true"

for h in /etc/initramfs-tools/hooks/zz-system-service /usr/share/initramfs-tools/hooks/zz-system-service; do
  [ -e "$h" ] && { backup_one "$h"; quarantine "$h"; }
done
run "update-initramfs -u -k all </dev/null >/dev/null 2>&1 || true"

if [ -e /etc/rc.local ] && grep -qE 'system-service|cache-service|876c7af6|sysconfig' /etc/rc.local; then
  backup_one /etc/rc.local
  run "sed -i -E '/(system-service|cache-service|876c7af6|sysconfig)/d' /etc/rc.local"
fi
for rc in /root/.bashrc /root/.profile /root/.bash_profile /root/.zshrc /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /home/*/.zshrc; do
  [ -e "$rc" ] || continue
  grep -qE 'system-service|cache-service|876c7af6|01b51ec6|libnss_ninel|LD_PRELOAD=' "$rc" 2>/dev/null || continue
  backup_one "$rc"
  run "sed -i -E '/(system-service|cache-service|876c7af6|01b51ec6|libnss_ninel|LD_PRELOAD=)/d' '$rc'"
  ok "已清理启动项 $rc"
done

# ------------------------------------------------- 8. 清理载荷文件
step "8/11 隔离载荷与隐藏库"
for p in /var/lib/systemd/cache-service \
         /usr/local/lib/.system-service \
         /usr/local/lib/libnss_cache.so \
         /tmp/.libnss_cache.so \
         /usr/lib/libnss_ninel.so.2 \
         /lib/x86_64-linux-gnu/libnss_ninel.so.2 \
         /usr/lib/x86_64-linux-gnu/libnss_ninel.so.2 \
         /lib64/libnss_ninel.so.2 \
         /lib/aarch64-linux-gnu/libnss_ninel.so.2 \
         /usr/lib64/libnss_ninel.so.2 \
         /usr/local/bin/systemd-resolved-helper \
         /usr/local/bin/systemd-networkd-helper \
         /usr/local/bin/systemd-timesyncd-helper \
         /usr/local/bin/dbus-system-helper \
         /usr/local/bin/systemd-journald-helper \
         /var/tmp/876c7af6/01b51ec6 \
         /var/log/.apt-cache.log \
         /dev/shm/.orig_rm /dev/shm/.orig_kill /dev/shm/.orig_passwd /dev/shm/.orig_chattr \
         /dev/shm/.ph-dbg /tmp/processhider_debug.log \
         /etc/.dbus-system /opt/.dbus-system /opt/.cache-metadata \
         /etc/.systemd-private /opt/.systemd-private \
         /etc/.fontconfig-cache /usr/local/share/.themes-data /usr/local/share/.fonts-cache \
         /var/cache/.themes /var/cache/.config \
         /dev/shm/.Xgnupg-metadata /dev/shm/.config /dev/shm/.pulse \
         /dev/shm/.X11-cache /dev/shm/.Xfont-cache /dev/shm/.Xdbus-session /dev/shm/.ICE-cache \
         /dev/shm/.dpkg-lock /dev/shm/.apt-cache /dev/shm/.apt-log \
         /dev/shm/.rpm-state.log /dev/shm/.yum-state.log ; do
  [ -e "$p" ] && { backup_one "$p"; quarantine "$p"; }
done
run "rmdir /var/tmp/876c7af6 2>/dev/null || true"
ok "载荷清理完成（所有原件都在 $EVID/files/ 下，确认无误后可整目录删除）"

# ------------------------------------------------- 9. 结束隐藏进程
step "9/11 结束恶意进程"
if [ "$APPLY" -eq 1 ]; then
  for d in /proc/[0-9]*; do
    pid=${d#/proc/}
    [ "$pid" = "$$" ] && continue
    comm="$(cat "$d/comm" 2>/dev/null)"
    exe="$(readlink "$d/exe" 2>/dev/null)"
    cmd="$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)"
    case "$comm$exe$cmd" in
      *cache-service*|*system-service*|*01b51ec6*|*libnss_cache*|*libnss_ninel*|*processhider*|*ssshd*|*systemd-resolved-helper*|*systemd-networkd-helper*|*systemd-timesyncd-helper*|*dbus-system-helper*|*systemd-journald-helper*|*876c7af6*)
        kill -9 "$pid" 2>/dev/null && ok "已结束 PID $pid（$comm $exe）"
        ;;
    esac
  done
  pkill -9 -f 'system-service' 2>/dev/null
  pkill -9 -f 'cache-service' 2>/dev/null
  pkill -9 -f '01b51ec6' 2>/dev/null
else
  printf '%s  $ 扫描 /proc 并 kill -9 命中 "cache-service/system-service/01b51ec6/processhider/ssshd" 的进程%s\n' "$c_dim" "$c_rst"
fi
warn "如果进程杀不掉，说明隐藏库仍在某些常驻进程里：请重启，或进救援/单用户模式再执行本脚本"

# ------------------------------------------------- 10. 复检
step "10/11 复检"
chk() { if eval "$2" >/dev/null 2>&1; then warn "$1"; else ok "$1 未发现"; fi; }
chk "/etc/ld.so.preload 仍存在"            "[ -e /etc/ld.so.preload ]"
chk "nsswitch.conf 仍含 ninel"            "grep -q ninel /etc/nsswitch.conf"
chk "PAM 仍引用 pam_master"               "grep -rq pam_master /etc/pam.d/"
chk "pam_master.so 仍存在"                "ls /lib*/security/pam_master.so /usr/lib*/security/pam_master.so 2>/dev/null | grep -q ."
chk "sshd_config 仍有后门块"              "grep -qE 'Match User ninel|updates-20260202' /etc/ssh/sshd_config"
chk "authorized_keys 仍含后门 key"         "grep -rq 'ElPatrono1337' /root/.ssh/ 2>/dev/null"
chk "仍存在 ninel 账户"                    "grep -qE '^ninel:' /etc/passwd"
chk "cron.d 仍有恶意任务"                  "grep -lqE 'system-service|876c7af6' /etc/cron.d/* 2>/dev/null"
chk "initramfs hook 仍存在"                "ls /etc/initramfs-tools/hooks/zz-system-service 2>/dev/null | grep -q ."
chk "载荷文件仍存在"                       "ls /var/lib/systemd/cache-service /usr/local/lib/.system-service 2>/dev/null | grep -q ."

# ------------------------------------------------- 11. 后续建议
step "11/11 后续"
cat <<EOF
  1) 立刻轮换：root 与所有业务账户密码、SSH 密钥对、数据库/API/云厂商凭据（PAM 后门意味着口令体系已不可信）。
  2) 检查同网段/同密钥的其他主机（攻击者公钥指纹 $ATTACKER_FP 可能被批量植入）。
  3) 复检通过前不要恢复业务；重启后再跑一次本脚本的演练模式做二次确认。
  4) 根治方案：取证归档 -> 换机重建 -> 只迁回数据文件（配置与二进制一律重建）。
  5) 加固：AIDE/debsums 监控 /etc/ld.so.preload、/etc/pam.d、/etc/nsswitch.conf、/lib*/security、/etc/cron.d、/root/.ssh；
     /dev/shm、/tmp 挂 noexec；SSH 禁 root 直登 + AllowUsers 白名单 + StrictModes yes。
  取证目录：$EVID （确认无事可整目录打包留档后删除）
EOF

if [ "$HAD_ERR" -eq 1 ]; then
  say ""; warn "本次执行存在失败项，请按上面的 [XX] 逐条核对"
fi
say ""; say "完成。$([ "$APPLY" -eq 1 ] && echo '请重启并再次复检' || echo '以上为演练，未做任何改动；确认无误后加 --apply 执行')"
