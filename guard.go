// guard.go —— 常驻守护：免疫 + 实时监控 + 自动回滚 + 自愈
//
// 设计目标（对应需求）：
//   1. 免疫：在木马的所有落点路径上预置"占位陷阱"（不可变目录），使木马无法创建文件；
//      并把 /etc/ld.so.preload 设为不可变空文件，直接废掉它最关键的全局注入。
//   2. 检测到它改动了任何关键文件 → 立刻按最小范围改回去（不是整文件覆盖，避免冲掉管理员改动）。
//   3. 检测到病毒本体 → 先断持久化、再杀进程、再删文件。
//   4. 启动时若已中招 → 自动执行完整清除，然后进入守护。
//   5. 自愈：本守护自身的 unit / 二进制被删掉，几秒内自动恢复。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func syscallIoctl(fd uintptr, cmd uintptr, flags *int32) (uintptr, uintptr, syscall.Errno) {
	return syscall.Syscall(syscall.SYS_IOCTL, fd, cmd, uintptr(unsafe.Pointer(flags)))
}

const (
	guardName    = "rkk"
	guardDir     = "/var/lib/rkk"
	guardBackups = "/var/lib/rkk/backups"
	guardLog     = "/var/log/rkk.log"
	guardBin     = "/usr/local/sbin/rkk"
	guardBinAlt  = "/usr/lib/rkk/rkk"
	guardUnit    = "/etc/systemd/system/rkk.service"
	guardConf    = "/etc/rkk.conf"
	vaccineMark  = ".rkk-vaccine"
)

type guardConfig struct {
	Interval   int  // 巡检间隔（秒）
	Aggressive bool // 是否连 node 账户一起清
}

func loadConfig() guardConfig {
	cfg := guardConfig{Interval: 2}
	if s := readSmall(guardConf, 64<<10); s != "" {
		for _, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			switch k {
			case "interval":
				if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 300 {
					cfg.Interval = n
				}
			case "aggressive":
				cfg.Aggressive = v == "1" || v == "true" || v == "yes"
			}
		}
	}
	return cfg
}

func guardLogf(format string, a ...any) {
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, a...))
	if rootDir != "" {
		fmt.Print(line)
		return
	}
	if fi, err := os.Stat(rp(guardLog)); err == nil && fi.Size() > 5<<20 {
		_ = os.Rename(rp(guardLog), rp(guardLog)+".1")
	}
	f, err := os.OpenFile(rp(guardLog), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		fmt.Print(line)
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}

// ------------------------------------------------------------ 不可变属性

func setImmutable(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var flags int32
	_, _, _ = syscallIoctl(f.Fd(), fsIOCGetFlags, &flags)
	flags |= fsImmutable
	_, _, e := syscallIoctl(f.Fd(), fsIOCSetFlags, &flags)
	if e != 0 {
		return fmt.Errorf("ioctl setflags: %v", e)
	}
	return nil
}

// ------------------------------------------------------------ 免疫（疫苗）

// 木马会用到的全部落点：载荷文件、伪装目录、伪造 unit、恶意 cron、initramfs hook
func vaccineTargets() []string {
	var ts []string
	ts = append(ts, payloadPaths...)
	ts = append(ts, decoyDirs...)
	ts = append(ts, "/var/tmp/876c7af6")
	ts = append(ts, "/dev/shm/.orig_rm", "/dev/shm/.orig_kill", "/dev/shm/.orig_passwd", "/dev/shm/.orig_chattr")
	ts = append(ts, "/etc/initramfs-tools/hooks/zz-system-service")
	for _, n := range maliciousCronNames {
		ts = append(ts, "/etc/cron.d/"+n)
	}
	for _, n := range maliciousUnitNames {
		ts = append(ts, "/etc/systemd/system/"+n+".service")
	}
	// 去重：若父目录已在列表里（父目录不可变后子路径自然写不进来），子路径不再单独布防
	sort.Strings(ts)
	var out []string
	for _, t := range ts {
		dup := false
		for _, o := range out {
			if t == o || strings.HasPrefix(t, o+"/") {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, t)
		}
	}
	return out
}

// 在目标路径预置不可变占位目录：木马 open(O_CREAT) 会拿到 EISDIR，
// 既写不进、也删不掉（chattr +i 连 root 都改不了，除非先 -i）。
func immunize() int {
	n := 0
	for _, t := range vaccineTargets() {
		t = rp(t)
		if fi, err := os.Lstat(t); err == nil {
			if fi.IsDir() && fileExists(t+"/"+vaccineMark) {
				if rootDir == "" && !isImmutable(t) {
					_ = setImmutable(t)
					n++
				}
				continue
			}
			if fi.IsDir() {
				// 清理后残留的空目录：接管为疫苗占位
				if ents, e := os.ReadDir(t); e == nil && len(ents) == 0 {
					_ = os.Remove(t)
				} else {
					continue
				}
			} else if fi.IsDir() == false {
				continue // 已存在真实文件（可能正是病毒），交给清除流程
			}
		}
		if err := os.MkdirAll(filepath.Dir(t), 0755); err != nil {
			continue
		}
		if err := os.Mkdir(t, 0755); err != nil {
			continue
		}
		_ = os.WriteFile(t+"/"+vaccineMark, []byte("created by rkk; do not remove\n"), 0644)
		if rootDir != "" {
			n++
			continue
		}
		if err := setImmutable(t); err == nil {
			n++
		}
	}
	// 最关键的一步：把全局注入点锁成空文件
	pre := rp("/etc/ld.so.preload")
	if fi, err := os.Lstat(pre); err != nil {
		_ = os.MkdirAll(filepath.Dir(pre), 0755)
		if err := os.WriteFile(pre, nil, 0644); err == nil {
			if rootDir == "" {
				_ = setImmutable(pre)
			}
			n++
		}
	} else {
		if content := readSmall("/etc/ld.so.preload", 64<<10); containsAny(content, "libnss_cache", "ninel", ".system-service") {
			// 有恶意行：先交给清除流程处理，此处不覆盖
			return n
		}
		if !fi.IsDir() && !isImmutable(pre) && rootDir == "" {
			if err := setImmutable(pre); err == nil {
				n++
			}
		}
	}
	return n
}

func isImmutable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var flags int32
	_, _, _ = syscallIoctl(f.Fd(), fsIOCGetFlags, &flags)
	return flags&fsImmutable != 0
}

func unimmunize() int {
	if rootDir != "" {
		return 0
	}
	n := 0
	if isImmutable(rp("/etc/ld.so.preload")) {
		clearImmutable(rp("/etc/ld.so.preload"))
		n++
	}
	for _, t := range vaccineTargets() {
		t = rp(t)
		if fi, err := os.Lstat(t); err == nil && fi.IsDir() && fileExists(t+"/"+vaccineMark) {
			clearImmutable(t)
			_ = os.Remove(t + "/" + vaccineMark)
			if err := os.Remove(t); err == nil {
				n++
			}
		}
	}
	return n
}

func vaccineCount() int {
	n := 0
	for _, t := range vaccineTargets() {
		if isVaccine(rp(t)) {
			n++
		}
	}
	return n
}

// ------------------------------------------------------------ 清除（守护内部调用）

func runGuardClean(aggr bool) *Cleaner {
	ts := time.Now().Format("20060102-150405")
	dir := filepath.Join(guardBackups, ts)
	_ = os.MkdirAll(rp(dir), 0700)
	c := &Cleaner{BackupDir: rp(dir), aggr: aggr, quiet: true}

	c.cleanCron()
	c.cleanSystemd()
	c.cleanInitramfs()
	c.cleanRc()

	for round := 0; round < 3; round++ {
		var pids []int
		for _, p := range scanProcs() {
			if ok, _ := p.match(); ok {
				pids = append(pids, p.PID)
			}
		}
		if len(pids) == 0 {
			break
		}
		killPIDs(pids)
		time.Sleep(200 * time.Millisecond)
	}

	c.cleanPreload()
	c.cleanNsswitch()
	c.cleanPam()
	c.cleanSSH()
	c.cleanAccounts()
	c.cleanPayloads()
	return c
}

// ------------------------------------------------------------ 巡检

func patrolOnce(cfg guardConfig) {
	// 1) 感染判定：任何一项命中就整体处置（先断持久化，再杀进程，最后删文件）
	if fs := doScan(); len(fs) > 0 {
		guardLogf("发现 %d 项感染痕迹，开始自动清除", len(fs))
		for _, f := range fs {
			guardLogf("  · [%s] %s — %s", f.Kind, f.Target, f.Detail)
		}
		c := runGuardClean(cfg.Aggressive)
		for _, l := range c.Log {
			guardLogf("  %s", l)
		}
		guardLogf("清除完成：变更 %d，失败 %d", c.Changed, c.Failed)
		// 清除后立刻重新布防
		if n := immunize(); n > 0 {
			guardLogf("重新布防 %d 个落点", n)
		}
	}

	// 2) 疫苗维护：被 chattr -i / 被删除的占位陷阱，几秒内补回
	missing := 0
	for _, t := range vaccineTargets() {
		tt := rp(t)
		fi, err := os.Lstat(tt)
		if err != nil || !fi.IsDir() || !fileExists(tt+"/"+vaccineMark) {
			missing++
		} else if rootDir == "" && !isImmutable(tt) {
			missing++
		}
	}
	if missing > 0 {
		if n := immunize(); n > 0 {
			guardLogf("补回 %d 处疫苗占位（原缺失 %d 处）", n, missing)
		}
	}
	// preload 被还原成可写 → 重新加锁
	if rootDir == "" {
		if fi, err := os.Lstat(rp("/etc/ld.so.preload")); err == nil && !fi.IsDir() {
			if content := readSmall("/etc/ld.so.preload", 64<<10); !containsAny(content, "libnss_cache", "ninel", ".system-service") && !isImmutable(rp("/etc/ld.so.preload")) {
				_ = setImmutable(rp("/etc/ld.so.preload"))
				guardLogf("/etc/ld.so.preload 被解锁，已重新设为不可变")
			}
		}
	}

	// 3) 自愈：unit / 二进制被删，立刻恢复
	healSelf()
}

func healSelf() {
	if rootDir != "" {
		return
	}
	if !fileExists(guardBin) || !fileExists(guardBinAlt) {
		if exe, err := os.Executable(); err == nil && exe != rp(guardBin) {
			_ = os.MkdirAll(filepath.Dir(rp(guardBin)), 0755)
			_ = os.MkdirAll(filepath.Dir(rp(guardBinAlt)), 0755)
			_ = copyFile(exe, rp(guardBin), 0755)
			_ = copyFile(exe, rp(guardBinAlt), 0700)
			guardLogf("守护二进制被删除，已从 %s 恢复", exe)
		}
	}
	if !fileExists(guardUnit) {
		if err := writeGuardUnit(); err == nil {
			guardLogf("守护 unit 被删除，已重建并重新启用")
			_, _ = runCmd(30*time.Second, "systemctl", "daemon-reload")
			_, _ = runCmd(30*time.Second, "systemctl", "enable", "--now", guardName)
		}
	}
}

func writeGuardUnit() error {
	unit := `[Unit]
Description=System Integrity Guard (rkk)
After=network.target
DefaultDependencies=no

[Service]
Type=simple
ExecStart=` + guardBin + ` run
Restart=always
RestartSec=3
Nice=-5
OOMScoreAdjust=-500

[Install]
WantedBy=multi-user.target
`
	return writeAtomic(guardUnit, unit, 0644)
}

func writeGuardConf(cfg guardConfig) error {
	aggr := 0
	if cfg.Aggressive {
		aggr = 1
	}
	body := fmt.Sprintf(`# rkk 配置
interval=%d
aggressive=%d
`, cfg.Interval, aggr)
	return writeAtomic(guardConf, body, 0644)
}

// ------------------------------------------------------------ 子命令

func cmdInstall(args []string) {
	yes := hasFlag(args, "-y") || hasFlag(args, "--yes") || hasFlag(args, "-yes")
	aggr := hasFlag(args, "-aggressive")

	if os.Geteuid() != 0 && rootDir == "" {
		fmt.Println("错误：安装需要 root")
		os.Exit(2)
	}

	fmt.Printf("rkk v%s 安装计划\n", version)
	fmt.Println("  1) 体检：若已中招，先完整清除（自动备份）")
	fmt.Println("  2) 布防：在木马落点预置不可变占位，并锁定 /etc/ld.so.preload")
	fmt.Println("  3) 常驻：安装 systemd 服务，每 2 秒巡检，改动即刻改回、有病毒即刻清除")
	fmt.Println("  4) 自愈：服务自身被删也会自动恢复")
	if !yes {
		fmt.Print("\n输入 yes 继续：")
		var in string
		fmt.Scanln(&in)
		if strings.TrimSpace(strings.ToLower(in)) != "yes" {
			fmt.Println("已取消。")
			return
		}
	}

	cfg := guardConfig{Interval: 2, Aggressive: aggr}

	// 1) 体检 + 清除
	if fs := doScan(); len(fs) > 0 {
		fmt.Printf("\n[1/4] 发现 %d 项感染痕迹，开始清除\n", len(fs))
		c := runGuardClean(aggr)
		for _, l := range c.Log {
			fmt.Println("      " + l)
		}
		fmt.Printf("      清除完成：变更 %d，失败 %d\n", c.Changed, c.Failed)
	} else {
		fmt.Println("\n[1/4] 体检通过，未发现感染")
	}

	// 2) 布防
	n := immunize()
	fmt.Printf("\n[2/4] 已布防 %d 处（不可变占位 + ld.so.preload 锁定）\n", n)

	// 3) 安装自身
	exe, err := os.Executable()
	if err != nil {
		fmt.Println("错误：无法定位自身可执行文件")
		os.Exit(1)
	}
	_ = os.MkdirAll(rp("/usr/local/sbin"), 0755)
	_ = os.MkdirAll(rp("/usr/lib/rkk"), 0755)
	if err := copyFile(exe, rp(guardBin), 0755); err != nil {
		fmt.Printf("错误：复制到 %s 失败：%v\n", guardBin, err)
		os.Exit(1)
	}
	_ = copyFile(exe, rp(guardBinAlt), 0700)
	_ = writeGuardConf(cfg)
	_ = os.MkdirAll(rp(guardDir), 0700)
	_ = os.MkdirAll(rp(guardBackups), 0700)

	fmt.Printf("\n[3/4] 已安装：%s（备份副本 %s）\n", guardBin, guardBinAlt)

	if err := writeGuardUnit(); err != nil {
		fmt.Printf("错误：写入 systemd unit 失败：%v\n", err)
		os.Exit(1)
	}
	if _, err := runCmd(30*time.Second, "systemctl", "daemon-reload"); err != nil {
		fmt.Println("警告：systemctl daemon-reload 失败，请手工执行")
	}
	if _, err := runCmd(40*time.Second, "systemctl", "enable", "--now", guardName); err != nil {
		fmt.Println("警告：服务启动失败，请手工 systemctl enable --now rkk")
	}

	// 4) 状态
	time.Sleep(1 * time.Second)
	fmt.Println("\n[4/4] 运行状态")
	fmt.Printf("      systemd: %s  布防点: %d 个\n", systemctlState(), vaccineCount())
	fmt.Printf("      日志: %s\n", guardLog)
	fmt.Println("\n完成。以后：rkk status 看状态，rkk uninstall 卸载（会解除所有锁定）。")
}

func cmdPatrol(args []string) {
	cfg := loadConfig()
	if hasFlag(args, "-aggressive") {
		cfg.Aggressive = true
	}
	fmt.Printf("rkk patrol（间隔 %ds，aggressive=%v）\n", cfg.Interval, cfg.Aggressive)
	patrolOnce(cfg)
	fmt.Println("巡检完成")
}

func cmdRun(args []string) {
	cfg := loadConfig()
	guardLogf("守护启动（间隔 %ds，aggressive=%v，pid=%d）", cfg.Interval, cfg.Aggressive, os.Getpid())

	// 启动即体检：已中招则先清
	if fs := doScan(); len(fs) > 0 {
		guardLogf("启动体检：发现 %d 项感染，先清除", len(fs))
		c := runGuardClean(cfg.Aggressive)
		guardLogf("启动清除完成：变更 %d，失败 %d", c.Changed, c.Failed)
	}
	immunize()

	lastBeat := time.Now()
	tick := time.NewTicker(time.Duration(cfg.Interval) * time.Second)
	defer tick.Stop()
	for range tick.C {
		patrolOnce(cfg)
		if time.Since(lastBeat) > 30*time.Minute {
			guardLogf("心跳：布防 %d 个，运行正常", vaccineCount())
			lastBeat = time.Now()
		}
	}
}

func systemctlState() string {
	out, err := runCmd(15*time.Second, "systemctl", "is-active", guardName)
	act := strings.TrimSpace(out)
	if i := strings.IndexByte(act, '\n'); i >= 0 {
		act = act[:i]
	}
	if err != nil || act == "" || strings.Contains(act, "Failed") || strings.Contains(act, "not been booted") || strings.Contains(act, "unknown") {
		return "未运行（当前环境无 systemd 或服务未安装）"
	}
	return act
}

func cmdStatus(args []string) {
	cfg := loadConfig()
	fmt.Printf("rkk v%s\n\n", version)
	act := systemctlState()
	fmt.Printf("服务状态 : %s\n", act)
	fmt.Printf("巡检间隔 : %ds\n", cfg.Interval)
	fmt.Printf("aggressive: %v\n", cfg.Aggressive)
	fmt.Printf("布防点   : %d / %d\n", vaccineCount(), len(vaccineTargets()))
	locked := ""
	if fi, err := os.Lstat(rp("/etc/ld.so.preload")); err == nil && !fi.IsDir() {
		if isImmutable(rp("/etc/ld.so.preload")) {
			locked = "已锁定（不可变）"
		} else {
			locked = "未锁定"
		}
	} else {
		locked = "不存在"
	}
	fmt.Printf("ld.so.preload: %s\n", locked)

	n := len(doScan())
	if n == 0 {
		fmt.Println("当前感染 : 未发现")
	} else {
		fmt.Printf("当前感染 : %d 项（守护会立即处置；若持续出现说明有更高权限对手在反复写入）\n", n)
	}

	if s := readSmall(guardLog, 5<<20); s != "" {
		lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
		if len(lines) > 15 {
			lines = lines[len(lines)-15:]
		}
		fmt.Println("\n最近日志：")
		for _, l := range lines {
			fmt.Println("  " + l)
		}
	}
}

func cmdImmunize(args []string) {
	n := immunize()
	fmt.Printf("已布防 %d 处；当前布防点合计 %d / %d\n", n, vaccineCount(), len(vaccineTargets()))
	if isImmutable(rp("/etc/ld.so.preload")) {
		fmt.Println("/etc/ld.so.preload 已设为不可变空文件（木马无法再写入全局注入）")
	}
}

func cmdUninstall(args []string) {
	if os.Geteuid() != 0 && rootDir == "" {
		fmt.Println("错误：卸载需要 root")
		os.Exit(2)
	}
	_, _ = runCmd(30*time.Second, "systemctl", "stop", guardName)
	_, _ = runCmd(30*time.Second, "systemctl", "disable", guardName)
	_ = forceRemove(guardUnit)
	_, _ = runCmd(30*time.Second, "systemctl", "daemon-reload")
	n := unimmunize()
	_ = forceRemove(guardBin)
	_ = forceRemove(guardBinAlt)
	_ = forceRemove(guardConf)
	fmt.Printf("已卸载：解除 %d 处布防，服务已停止\n", n)
	fmt.Printf("保留：%s（备份与日志）、%s\n", guardDir, guardLog)
}

func hasFlag(args []string, f string) bool {
	for _, a := range args {
		if a == f {
			return true
		}
	}
	return false
}
