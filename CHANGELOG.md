# Changelog

## [1.1.3] - 2026-11-21

依据受害机 154.219.110.37 的取证报告补齐四类检测：

### Added
- **已知哈希比对**：7 个文件哈希（木马本体、libnss_cache.so、隐藏器、`/dev/shm/.orig_*` 原件）。
  只对大小合适的文件算哈希，扫描深度限制 3 层。
- **NSS 隐藏账户**：`getent passwd` 有、`/etc/passwd` 没有的账户（`ninel` 就是这么藏起来的）。
  这是本家族最隐蔽的一环——纯读文件永远发现不了。
- **幻影 crontab**：`crontab -l` 有条目但 `/var/spool/cron/crontabs/root` 缺失/为空，
  或条目含 `/var/tmp/`、`disown`。
- **关键命令被替换**：`dpkg -V` 只筛 `/bin/ls`、`/bin/rm`、`/usr/bin/passwd`、`chattr`、`kill`、`apt` 等
  关键二进制（全量 `dpkg -V` 噪声太大，不采用）。

### Fixed
- `crontab -l` 输出的 `no crontab for xxx` 曾被当成条目，导致误报；现在先过滤提示语，
  且只认 5 段或 `@` 开头的真条目；spool 无权限读取时不下结论。



## [1.1.2] - 2026-11-21

### Added
- 隐藏库扫描目录补齐 `lib` 全路径：`/usr/lib64`、`/usr/lib/x86_64-linux-gnu`、
  `/usr/lib/aarch64-linux-gnu`、`/lib`、`/lib64`、`/lib/x86_64-linux-gnu`。
  第二阶段实测确认 `libnss_ninel.so.2.hider.<pid>` 会被投到这几处。
- 0 字节占位单独提示："安装器已就位，等 C2 下发真实载荷"。

### Fixed
- **内核线程误报**：`[khugepaged]`、`[watchdog/0]` 这类无 `exe`、`comm` 带方括号的
  进程不再计入。
- **运维自伤误报**：`bash`/`grep`/`tail`/`systemctl` 等排障命令因为命令行里带了关键字
  而被判定为木马进程的情况已排除；环境变量标记仍然优先。

### Tools
- 新增 `tools/lab-fullstate.sh`：合成全链终态自检，验证检出与清除（PASS）

### 动态验证依据
systemd 真启动环境采样：T+90s 19 项 → T+240s 21 项 → T+360s 22 项（仍在增长）。
直读确认 `/etc/ld.so.preload` 不存在、`nsswitch` 未注入 `ninel`、`pam.d` 无 `pam_master`，
六个 `libnss_ninel.so.2.hider.*` 全为 0 字节 → 真实载荷依赖 C2 下发。



## [1.1.1] - 2026-11-19

### Added
- **隐藏库副本规则**：按文件名形态匹配 `*.hider.<pid>`。这是本家族隐藏库落地时的通用命名
  （如 `libnss_cache.so.hider.89`、`.system-service.hider.89`、`.X-systemd.hider.89`），
  PID 每次都变，因此不依赖固定路径。
- 覆盖目录：`/etc`、`/etc/cron.d`、`/etc/pam.d`、`/etc/ssh`、`/usr/local/{lib,share,bin}`、
  `/usr/bin`、`/usr/lib`、`/dev/shm`、`/tmp`、`/var/tmp`、`/var/log`。
- 清除阶段同步删除隐藏库副本（先备份）。

### Changed
- 扫描结果按目标路径去重，同一文件不再重复出现在多个分类下。

### 动态验证依据
在隔离 VM（无网卡、initramfs 根、假 C2 仅回环）内真实执行样本，480 秒四段采样：
T+120s 命中 9 项 → T+240s 命中 11 项 → T+360/480s 持平。
本规则对应的正是 T+120s 就已出现的 `.hider.<pid>` 副本。


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
