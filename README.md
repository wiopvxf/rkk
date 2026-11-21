# rkk — Linux rootkit 免疫 · 巡检 · 自动清除

> 一个静态单文件的 Go 工具，专门对付 **child.malware / ninel / pam_master / processhider** 这一族
> Linux rootkit。它能**预防**这类木马落地、在被改动后**秒级改回**、发现本体后**自动清除**，
> 并且自身被杀/被删后会**自愈**。

[English summary ↓](README_en.md)

---

## 这个项目解决什么问题

2026 年 11 月，一台 Debian 11 服务器被植入了一族 rootkit。它做了一件很"聪明"的事：

```c
// 把自己写进全局预加载列表
/usr/local/lib/libnss_cache.so   →   /etc/ld.so.preload
```

于是机器上**所有动态链接的程序**（`ls`、`ps`、`find`、`rm`、`kill`、`ss`、`last`、`top`…）
在启动时都会先加载它的库。这个库导出了 100+ 个钩子，做了这些事：

- 把木马进程从 `/proc`、`ps`、`top` 里**抹掉**
- 把文件名/目录项从 `readdir`、`getdents64` 里**过滤掉**
- 把 `/proc/net/*` 的连接**隐藏掉**（`ss` 看不到 C2）
- 把 `utmp/wtmp/btmp` 的登录记录**篡改**（`last` 看不到入侵痕迹）
- 把 `rm`、`kill`、`chattr` 换成"假动作版"——你以为删了，其实没删

所以在这台机器上用常规手段清理，**你看到的一切都可能是假的**。

`rkk` 的应对思路很简单：**不跟它玩 libc**。全静态编译（`CGO_ENABLED=0`），
不经过 `ld.so`、不调用 libc，删除与发信号走裸 syscall。它读到的 `/proc` 和目录是真实的。

---

## 四个能力

| 能力 | 实现 |
|---|---|
| **① 免疫** | 在木马 76 个固定落点预置「不可变占位目录 + `.rkk-vaccine` 标记 + `chattr +i`」，并锁死 `/etc/ld.so.preload`（不可变空文件）。木马 `open(O_CREAT)` 拿到 `EISDIR`，写不进；想 `rm` 占位再写，`+i` 连 root 都删不掉 |
| **② 秒级回滚** | 每 2 秒巡检，**按最小范围**改回：只摘掉恶意那一行/那一块，不整文件覆盖，不冲掉管理员后来的正常配置 |
| **③ 自动清除** | 检测到本体 → 先断持久化（cron / systemd / initramfs）→ 再杀进程（3 轮，防看门狗互拉）→ 最后删文件（先备份、大文件记 SHA-256） |
| **④ 自愈** | systemd `Restart=always` + `RestartSec=3`；二进制双份互备；unit 或二进制被删，下一次巡检自动重建 |

---

## 快速开始

```sh
# 只扫描，不改任何东西
./rkk-linux-amd64

# 清除一次（自动备份到 /var/lib/rkk-guard/backups/）
./rkk-linux-amd64 clean -yes

# 装成守护：体检 → 布防 → 常驻 → 自愈
./rkk-linux-amd64 install
```

安装时会先体检，**已中招就先清干净**，然后布防、注册 systemd 服务。

```sh
./rkk-linux-amd64 status      # 服务状态 / 布防点数 / ld.so.preload 锁定状态 / 最近日志
./rkk-linux-amd64 immunize    # 只布防，不装服务
./rkk-linux-amd64 uninstall   # 停服务 + 解除全部 lockdown（卸载干净）
```

参考 [`docs/使用说明.md`](docs/使用说明.md)。

---

## 它具体拦什么、改回什么

**布防点** 覆盖木马的已知全部落点（含同家族变种）：

```
/var/lib/systemd/cache-service        /usr/local/lib/.system-service
/usr/local/lib/libnss_cache.so        /tmp/.libnss_cache.so
/lib/security/pam_master.so           /usr/lib/security/pam_master.so
/lib/x86_64-linux-gnu/libnss_ninel.so.2   /lib/aarch64-linux-gnu/…
/etc/.pm                              /var/tmp/updates-20260202
/var/tmp/876c7af6                     /var/log/.apt-cache.log
/etc/cron.d/systemd-timers 等 3 个     /etc/initramfs-tools/hooks/zz-system-service
/etc/systemd/system/{12 个伪造 unit}
/dev/shm/.orig_rm|.orig_kill|.orig_passwd|.orig_chattr
…以及 /etc/.fontconfig-cache 等伪装目录
```

**抗变种（1.1.0 起）**：固定落点会被改（同家族换机器时把 `/var/tmp/876c7af6` 换成别的随机名），所以额外加了一层**内容扫描**——不认文件名、只认内容，凡出现 `.x/black3` 或 `digitaldatainsights` 的文件即判定为下载器/持久化脚本。换名换目录照样抓到。

**隐藏库副本（1.1.1 起）**：按文件名形态抓 `*.hider.<pid>`，覆盖 `/etc`、`/usr/local`、`/dev/shm`、`/tmp`、`/var/log` 等 13 个目录，不依赖固定路径。

**0 字节占位（1.1.2 起）**：命中 `*.hider.<pid>` 且大小为 0 时，提示"安装器已就位、等 C2 下发真实载荷"——这是比等 `ld.so.preload` 更早的窗口。


## 自检（不需要真感染）

```bash
./tools/lab-fullstate.sh            # 或传入自编译的 rkk 路径
```

它会在临时目录（`RKK_ROOT` 限定）重建一份完整感染终态：`ld.so.preload` 注入、
`nsswitch` 插入 `ninel`、`pam.d` 植入 `pam_master`、`ssshd` 后门、伪造 unit、
攻击者公钥、后门账户…… 然后验证两件事：

1. **检出**：全部痕迹都要报出来；
2. **清除**：删对文件、并把配置文件精准修复（`nsswitch` 只去掉 `ninel`，保留 `hosts` 行）。

全部通过才会 `RESULT: PASS`。整个过程不碰真实 `/etc`。

**回滚方式**：

| 被改的地方 | 怎么改回 |
|---|---|
| `/etc/ld.so.preload` | 只删恶意行 |
| `/etc/nsswitch.conf` | 从 `passwd/shadow/group` 行摘掉 `ninel`，其余原样保留 |
| `/etc/pam.d/*` | 优先用木马自己的 `.pm-bak` 还原（**仅当备份本身干净**），否则按行删 `pam_master` |
| `/etc/passwd|shadow|group|gshadow` | 只删 `ninel`（`-aggressive` 时连 `node`）那一行 |
| `/etc/sudoers.d/*` | 删 `99-ninel-root`；不用 `visudo` 覆盖 |
| `/etc/ssh/sshd_config` | 删 `Match User ninel` 块与 `StrictModes no`，保留 `Port` 等设置 |
| `authorized_keys` | 按**指纹**精确删攻击者公钥，**你的 key 不动** |
| cron / crontab | 删恶意文件、按行摘掉拉起命令 |
| systemd / initramfs / rc.local / .bashrc | 停服务、删 unit、重建 initramfs、按行摘掉 |
| 病毒本体 | 杀进程 → 删文件，备份 + SHA-256 留痕 |

全过程写 `/var/log/rkk-guard.log`（5MB 轮转）。

---

## 已验证

在隔离环境用真实样本构造了 30 个植入点的模拟感染目录：

| 测试 | 结果 |
|---|---|
| 布防后扫描 | 76 处占位被识别为「自己人」，只报真实病毒，无「删了建、建了删」抖动 |
| 首次巡检 | 自动清除 37 项变更，失败 0，随后自动补防 |
| 复检 | `未发现匹配特征。（已布防 76 处）` |
| 模拟再次入侵（加 `ninel`、投恶意 cron、丢回 40MB 载荷） | 下一次巡检全部改回，`passwd` 只剩 `root` |
| 占位抗写入 | 向落点写文件 → `Is a directory` |

---

## 威胁模型与限制（请先读这段）

1. **单机免疫，不是万能的。** 对方若已拿到 root，可以 `chattr -i` 拆占位，守护 2 秒内补回——
   但**这 2 秒就是窗口**。真正的"打不进来"要靠入口治理：关掉不必要对外服务、修上传/命令执行漏洞、改弱口令。
2. **会锁住 `/etc/ld.so.preload`。** 你以后手工改它需要先 `chattr -i`，改完 `+i`；或先 `uninstall`。
3. **不重装被替换的系统命令。** `rm/kill/chattr` 被 UPX 加壳时只告警，需要你自己
   `apt-get install --reinstall -y coreutils passwd util-linux`。
   ⚠️ **绝不能用 `/dev/shm/.orig_*` 恢复**——那是木马放的假副本（本项目已验证）。
4. **只识别这一族。** root + PAM 万能密码 + initramfs 持久化意味着信任链已断：本工具负责止血与防复发，
   **最终仍建议取证后重建系统**。
5. 仅用于**自有或已获授权主机**。

---

## 仓库结构

```
rkk/
├── README.md / README_en.md
├── LICENSE              MIT
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── go.mod
├── main.go              命令分发（scan/clean/install/run/status/immunize/uninstall）
├── core.go              特征库 + 扫描引擎 + 清除引擎
├── guard.go             免疫 / 巡检 / 自愈 / systemd 集成
├── docs/
│   ├── 木马分析报告.md    完整技术拆解（六阶段运行链、组件、IOC、不确定性）
│   ├── IOC清单.txt       分组 IOC（哈希/路径/账户/密钥/网络/环境变量）
│   ├── 应急清除脚本.sh    bash 版应急脚本（默认演练，--apply 执行）
│   ├── 举报材料.md       监管/abuse/情报平台三版材料
│   └── 使用说明.md       守护模式详细说明
├── samples/             ⚠️ 加密样本（不在 git 里，见 .gitignore）
│   ├── README.md
│   ├── malware-sample.zip   密码保护
│   └── SHA256SUMS.txt
├── tools/
│   └── make-test-fixture.sh  生成"无真实样本"的模拟感染目录，供开发自测
└── dist/                预编译二进制 + SHA256SUMS
```

## 构建

```sh
make build            # 本机
make cross            # amd64 / arm64 / 386
make test             # 生成测试夹具 + 跑巡检
```

---

## 关于样本（重要）

本仓库**不建议**把真实木马样本提交到公开仓库——主流平台的服务条款都禁止分发恶意软件，
账号会被封，也可能帮别人扩散。

本项目采用的方式：

- 样本单独打包为**加密 zip**（`samples/malware-sample.zip`，密码见 `samples/README.md`），
  只在私下分发；
- `samples/` 与 `dist/` 已写进 `.gitignore`；
- 公开仓库里只保留**哈希与 IOC**（`docs/IOC清单.txt`、`samples/SHA256SUMS.txt`），
  研究者用哈希去民间样本库（如 MalwareBazaar / VirusTotal）自行获取。

如果你要发布，请确认：`git status` 里没有 `samples/`。

---

## 许可

MIT（见 [LICENSE](LICENSE)）。
样本文件不属于本项目的授权内容，仅用于安全研究与应急响应，**不得再分发**。

---

## 致谢与免责

分析基于 2026-11-14 从受害服务器采集的取证包，全程静态分析、未执行样本。
工具按"最小改动"原则设计，但任何自动修改系统配置的操作都有风险，请先在测试机验证。
