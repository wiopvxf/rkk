# Changelog

## 1.0.0 — 2026-11-14

首个公开版本。

- 特征库：覆盖 child.malware / ninel / pam_master / processhider 一族的 30 项检测点
  （载荷路径、伪装目录、ld.so.preload、nsswitch、PAM、SSH、sudoers、cron、systemd unit、
  initramfs hook、rc 文件、账户、公钥指纹、进程环境变量标记）。
- 清除引擎：9 步流程，先断持久化再杀进程再删文件；全部改动先备份，>8MB 载荷只记 SHA-256。
- 守护模式：`install / run / status / immunize / uninstall`。
- 免疫：76 个落点预置不可变占位，`/etc/ld.so.preload` 锁定为不可变空文件。
- 回滚：按最小范围（行/块）修复，保留管理员正常配置。
- 自愈：systemd 重启策略 + 二进制双份 + unit/二进制自动重建。
- 支持 `RKK_ROOT=/mnt/disk` 对离线镜像操作（救援/取证）。
- 兼容旧版 flag 风格：`-clean -yes -aggressive`。
