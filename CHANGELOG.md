# Changelog

## [1.1.0] - 2026-11-18

### Added
- 内容型检测（`scanDroppers`）：按文件内容匹配 `.x/black3`、`digitaldatainsights`，
  不再依赖固定目录名。同家族变种每次入侵会更换 `/var/tmp/<随机名>`，原规则会漏。
- 新增落点：`/usr/bin/.locatione`、`/var/tmp/.ladyg0g0/.pr1nc35`、`/var/tmp/*/.locatione`、`/var/tmp/*/.pr1nc35`。
- 新增进程关键字：`.x/black3`、`.locatione`、`.pr1nc35`。
- 新增 unit 内容特征：`ssshd`、`.x/black3`、`digitaldatainsights`。
- 清除阶段同步删除内容命中的下载器脚本（先备份）。

### Changed
- 扫描结果去重，同一目标不再重复列出。

### Tools
- 新增 `tools/lab-selftest.sh`：在真实主机上跑「仿真感染 → 检测 → 清除 → 复检」闭环，不使用真样本。


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
