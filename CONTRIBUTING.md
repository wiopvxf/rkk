# 贡献指南

## 加一个新变种的特征

特征全部集中在 `core.go` 顶部的几个列表里，加特征基本不用改逻辑：

| 变量 | 用途 |
|---|---|
| `payloadPaths` | 木马会落地的文件路径（同时用于布防） |
| `decoyDirs` | 木马创建的伪装目录 |
| `payloadGlobs` | 需要 glob 的路径模式（`*` 通配） |
| `maliciousCronNames` | `/etc/cron.d/` 下的恶意文件名 |
| `maliciousUnitNames` | 伪造 systemd unit 名 |
| `unitContentMarkers` | unit 内容关键字 |
| `rcLineMarkers` | rc.local / .bashrc 里的拉起命令关键字 |
| `procKeywords` / `envMarkers` | 进程命令行与进程环境变量标记 |
| `attackerFP` / `attackerComment` | 攻击者 SSH 公钥指纹与注释 |

改完跑 `make test` 验证不误伤、不重复报。

## 提交前自检

```sh
gofmt -l .            # 应为空
go vet ./...
make cross            # 三个架构都要能编
make test             # 夹具巡检应清零
```

## Pull Request

- 一个 PR 只做一件事（加特征 / 修 bug / 改文档分开提）。
- 说明**证据**：样本哈希、路径截图、`rkk scan` 输出。不要粘贴完整恶意代码。
- 新特征请同时更新 `docs/IOC清单.txt`。

## 不要做的事

- 不要提交真实木马样本（见 `.gitignore` 与 `SECURITY.md`）。
- 不要把"自动重装系统包""自动改 SSH 端口"等破坏性动作塞进默认流程。
