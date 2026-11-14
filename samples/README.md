# ⚠️ 恶意样本（默认不随仓库分发）

本目录在你的**本地压缩包**里包含 `malware-sample.zip`，内含 2026-11-14 从受害
Debian 11 服务器采集的真实木马文件。**公开仓库里不应出现这个 zip**（已在 `.gitignore` 中排除）。

## 解压

```sh
unzip malware-sample.zip      # 需要密码
```

密码：`rkk-sample-2026`

## 内容

| 文件 | 说明 |
|---|---|
| `child.malware` | 41 MB，UPX 4.24 加壳的 Go 静态 ELF 主载荷（内嵌 NSS/PAM/隐藏库三个模块） |
| `libnss_cache.so` | 14 KB，NSS 劫持模块（只对 `ninel` 返回伪造记录） |
| `libnss_cache.so.hider.*` | 进程/文件隐藏库（取证时被截断，ELF 头声明节表在 164,672） |
| `orig_rm` / `orig_kill` / `orig_passwd` / `orig_chattr` | **注意：不是原始 coreutils**，是同样 UPX 加壳的木马替换版 |
| `system-monitor.placeholder` | 0 字节占位 |

## 哈希

见 `SHA256SUMS.txt`。要点：

```
child.malware                      6b9e912f…bd9edf
libnss_cache.so                    2981d2bd…81d213
libnss_cache.so.hider.1969935      37716b71…15683
orig_rm                            bdb1e0ec…50ea2
```

## 不要做的事

- 不要在宿主机直接执行任何文件；
- 不要上传 VirusTotal 之外的公开平台（VT 上传会公开样本，注意脱敏）；
- 分析完销毁快照。

## 没有样本时怎么开发

```sh
../tools/make-test-fixture.sh /tmp/fakeroot   # 生成不含真实木马的模拟感染目录
RKK_ROOT=/tmp/fakeroot ../rkk-linux-amd64 scan
```
