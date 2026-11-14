# 安全说明

## 处理恶意样本

`samples/malware-sample.zip` 内含**真实可执行的木马**。请遵守：

- 只在**断网的隔离虚拟机或专用分析机**上解压、运行；
- 不要在 Windows / 有共享目录的环境里解压（`libnss_cache.so` 等为 Linux ELF，
  但样本包含攻击者公钥等敏感材料）；
- 不要上传到任何公开平台（GitHub / Gist / 公开网盘）——违反平台条款且扩散风险；
- 分析完销毁环境快照。

## 上报漏洞

如果你发现本工具**误删系统文件、导致 SSH/PAM 锁死、绕过免疫**等问题，
请勿直接提交公开 Issue，先发邮件给维护者（见仓库主页），附：

- 系统版本（`cat /etc/os-release`）
- `rkk status` 输出
- 相关日志：`/var/log/rkk-guard.log`、`/var/lib/rkk-guard/backups/*/actions.log`
- 触发步骤

**尤其欢迎**这类报告：某个合法软件也用到了本项目布防的路径（会造成误伤）。

## 本工具会改动系统的地方

为了让使用者清楚风险，这里逐条列出：

| 改动 | 位置 | 卸载是否还原 |
|---|---|---|
| 创建不可变占位目录（76 处） | 木马落点路径 | `uninstall` 会 `chattr -i` 并删除 |
| 把 `/etc/ld.so.preload` 设为不可变空文件 | `/etc/ld.so.preload` | 解除不可变属性 |
| 安装 systemd 服务 | `/etc/systemd/system/rkk-guard.service` | 停用并删除 |
| 安装二进制 | `/usr/local/sbin/`、`/usr/lib/rkk-guard/` | 删除 |
| 写配置文件 | `/etc/rkk-guard.conf` | 删除 |
| 备份 | `/var/lib/rkk-guard/backups/` | **保留**（取证） |
| 日志 | `/var/log/rkk-guard.log` | **保留** |

除此之外**不碰任何业务文件**（网站目录、数据库、用户数据）。

## 已知风险

- 2 秒巡检窗口：攻击者若有 root，可在窗口内写入。
- `chattr +i` 依赖文件系统支持（ext4/xfs/btrfs 支持；overlayfs、部分网络文件系统可能不支持，
  此时占位仍能阻止"就地写文件"，但可能被 `rmdir` 后重建）。
- 若系统里已有同名的**合法**文件（极罕见），布防会跳过并交给清除流程，不会被覆盖。
