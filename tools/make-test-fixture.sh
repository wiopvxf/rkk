#!/bin/sh
# 生成一个"模拟感染"的目录树，用于在没有真实样本的情况下自测。
# 用法：tools/make-test-fixture.sh /tmp/rkk-fixture
set -eu
R=${1:-/tmp/rkk-fixture}

rm -rf "$R"
for d in etc/pam.d etc/cron.d etc/sudoers.d etc/ssh etc/initramfs-tools/hooks \
         etc/systemd/system etc/systemd/system-generators \
         lib/security lib/x86_64-linux-gnu usr/local/lib usr/libexec usr/bin \
         root/.ssh var/lib/systemd var/tmp var/spool/cron/crontabs var/backups \
         dev/shm opt; do
  mkdir -p "$R/$d"
done

# 载荷（占位文件即可，检测按路径判定）
for f in /var/lib/systemd/cache-service /usr/local/lib/.system-service \
         /usr/local/lib/libnss_cache.so /lib/security/pam_master.so \
         /lib/x86_64-linux-gnu/libnss_ninel.so.2 /usr/bin/ssshd \
         /usr/libexec/.rm /usr/libexec/.kill /usr/libexec/.chatattr \
         /var/tmp/updates-20260202 /etc/.pm ; do
  [ -d "$R$(dirname $f)" ] || mkdir -p "$R$(dirname $f)"
  printf 'MALWARE-PLACEHOLDER (not real code)\n' > "$R$f"
done

# 伪装目录
mkdir -p "$R/etc/.fontconfig-cache" "$R/opt/.systemd-private" "$R/dev/shm/.Xgnupg-metadata"

# ld.so.preload
echo '/usr/local/lib/libnss_cache.so' > "$R/etc/ld.so.preload"

# nsswitch
printf 'passwd:         files ninel\nshadow:         files ninel\ngroup:          files ninel\nhosts:          files dns\n' > "$R/etc/nsswitch.conf"

# PAM
printf '# original\n@include common-auth\n' > "$R/etc/pam.d/common-auth.pm-bak"
printf 'auth       optional     pam_master.so\n@include common-auth\n' > "$R/etc/pam.d/common-auth"
printf 'account    optional     pam_master.so\n' > "$R/etc/pam.d/common-account"

# 账户
printf 'root:x:0:0:root:/root:/bin/bash\nninel:x:9999:9999::/dev/null:/bin/bash\nnode:x:1000:1000::/home/node:/bin/bash\n' > "$R/etc/passwd"
printf 'root:*:19000:0:99999:7:::\nninel:!:19000:0:99999:7:::\n' > "$R/etc/shadow"
printf 'root:x:0:\nsudo:x:27:node,ninel\n' > "$R/etc/group"

echo 'ninel ALL=(ALL:ALL) NOPASSWD:ALL' > "$R/etc/sudoers.d/99-ninel-root"
echo 'node ALL=(ALL:ALL) NOPASSWD:ALL'  > "$R/etc/sudoers.d/node"

# cron
printf '@reboot root /usr/local/lib/.system-service >/dev/null 2>&1 &\n*/15 * * * * root /usr/local/lib/.system-service\n' > "$R/etc/cron.d/systemd-timers"
printf '@reboot /var/tmp/876c7af6/./01b51ec6 >/dev/null 2>&1 &\n' > "$R/var/spool/cron/crontabs/root"

# systemd / initramfs
printf '[Service]\nExecStart=/usr/local/bin/systemd-resolved-helper\n' > "$R/etc/systemd/system/systemd-resolved-cache.service"
printf '#!/bin/sh\n/usr/local/lib/.system-service >/dev/null 2>&1 &\n' > "$R/etc/initramfs-tools/hooks/zz-system-service"

# 攻击者公钥（注释用于命中，内容为假 key，不含真实材料）
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIlegituserkey legit@user\n' > "$R/root/.ssh/authorized_keys"
printf 'ssh-rsa AAAAB3FAKEKEYFORFIXTUREONLY ElPatrono1337\n' >> "$R/root/.ssh/authorized_keys"

# sshd
printf 'Port 22\nPermitRootLogin yes\n\nMatch User ninel\n    AuthorizedKeysFile /var/tmp/updates-20260202\n    LogLevel QUIET\n\nUsePAM yes\n' > "$R/etc/ssh/sshd_config"

echo "夹具已生成：$R"
echo "自测：RKK_ROOT=$R ./rkk scan"
