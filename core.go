// rootkit-killer —— 针对 child.malware / ninel / pam_master / processhider 家族 Linux rootkit
// 的检测与清除工具。
//
// 设计要点：
//   1. 全静态编译（CGO_ENABLED=0），不经过 ld.so / libc，因此 /etc/ld.so.preload 里的
//      恶意库无法劫持本进程；它读到的 /proc、目录列表、文件内容都是真实的。
//   2. 只用 Go 原生 syscall（Kill / Ioctl），不依赖 /usr/bin/kill、rm、chattr 等
//      可能已被木马替换的命令。
//   3. 默认只读扫描；必须显式 -clean -yes 才会改动系统，改动前全部备份。
//
// 用法：
//   ./rkk                  扫描（只读）
//   ./rkk -clean -yes      执行清除（先备份）
//   ./rkk -clean -yes -aggressive   额外处理 node 账户等可疑但可能属业务的项
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const version = "1.0.0"

// rootDir 非空时所有文件操作都指向该目录（用于扫描/清理挂载的离线镜像）
var rootDir = os.Getenv("RKK_ROOT")

func rp(p string) string {
	if rootDir == "" {
		return p
	}
	if p == "/" {
		return rootDir
	}
	if strings.HasPrefix(p, rootDir+"/") { // 已经是带前缀的绝对路径，避免二次拼接
		return p
	}
	if strings.HasPrefix(p, "/") {
		return filepath.Join(rootDir, p)
	}
	return p
}

func glob(pattern string) ([]string, error) {
	return filepath.Glob(rp(pattern))
}

// ---------------------------------------------------------------- IOC 定义

// 载荷 / 隐藏库 / 后门模块的落点
var payloadPaths = []string{
	"/var/lib/systemd/cache-service",
	"/usr/local/lib/.system-service",
	"/usr/local/lib/libnss_cache.so",
	"/tmp/.libnss_cache.so",
	"/usr/lib/libnss_ninel.so.2",
	"/lib/x86_64-linux-gnu/libnss_ninel.so.2",
	"/usr/lib/x86_64-linux-gnu/libnss_ninel.so.2",
	"/lib64/libnss_ninel.so.2",
	"/lib/aarch64-linux-gnu/libnss_ninel.so.2",
	"/usr/lib64/libnss_ninel.so.2",
	"/usr/lib/security/pam_master.so",
	"/lib/security/pam_master.so",
	"/lib64/security/pam_master.so",
	"/lib/x86_64-linux-gnu/security/pam_master.so",
	"/lib/aarch64-linux-gnu/security/pam_master.so",
	"/usr/lib64/security/pam_master.so",
	"/usr/local/bin/systemd-resolved-helper",
	"/usr/local/bin/systemd-networkd-helper",
	"/usr/local/bin/systemd-timesyncd-helper",
	"/usr/local/bin/dbus-system-helper",
	"/usr/local/bin/systemd-journald-helper",
	"/usr/bin/ssshd",
	"/usr/libexec/.rm",
	"/usr/libexec/.kill",
	"/usr/libexec/.chatattr",
	"/usr/libexec/.apt",
	"/usr/libexec/.apt-cli",
	"/var/tmp/updates-20260202",
	"/var/log/.apt-cache.log",
	"/etc/.pm",
	"/etc/.dbus-system",
	"/opt/.dbus-system",
	"/opt/.cache-metadata",
	"/tmp/processhider_debug.log",
	"/dev/shm/.ph-dbg",
	"/var/tmp/876c7af6/01b51ec6",
}

// 伪装成系统缓存/配置的目录（木马自建，非用户数据）
var decoyDirs = []string{
	"/etc/.systemd-private",
	"/opt/.systemd-private",
	"/etc/.fontconfig-cache",
	"/usr/local/share/.themes-data",
	"/usr/local/share/.fonts-cache",
	"/var/cache/.themes",
	"/var/cache/.config",
	"/dev/shm/.Xgnupg-metadata",
	"/dev/shm/.config",
	"/dev/shm/.pulse",
	"/dev/shm/.X11-cache",
	"/dev/shm/.Xfont-cache",
	"/dev/shm/.Xdbus-session",
	"/dev/shm/.ICE-cache",
	"/dev/shm/.dpkg-lock",
	"/dev/shm/.apt-cache",
	"/dev/shm/.apt-log",
	"/dev/shm/.rpm-state.log",
	"/dev/shm/.yum-state.log",
}

var payloadGlobs = []string{
	"/etc/pam.d/*.pm-bak",
	"/etc/pam.d/*.pam-bak",
	"/etc/ssh/sshd_config.pm-bak",
	"/dev/shm/.orig_*",
	"/dev/shm/*.hider.*",
	"/usr/local/lib/*.hider.*",
	"/tmp/.libnss_cache.so*",
	"/var/tmp/876c7af6",
	"/tmp/.child-trace-*",
	"/tmp/.watchdog-trace-*",
}

var procKeywords = []string{
	"cache-service",
	".system-service",
	"01b51ec6",
	"876c7af6",
	"libnss_cache",
	"libnss_ninel",
	"pam_master",
	"processhider",
	"ssshd",
	"systemd-resolved-helper",
	"systemd-networkd-helper",
	"systemd-timesyncd-helper",
	"dbus-system-helper",
	"systemd-journald-helper",
	"ph-dbg",
}

var envMarkers = []string{
	"__CHILD_MARKER", "__WATCHDOG_MARKER", "__WATCHDOG_MONITOR", "__WATCHDOG_MASKED",
	"__DECOY__", "__MASKED__", "__BACKUP_CHECK", "LANG_OVERRIDE____", "LOCAL_FLAG",
	"INITIALIZED_STATE_", "__CHILD_PROCESS_NAME", "__CMDLINE_MASKED", "__SELECTED_NAME",
	"MARINICA_BISCUITE",
}

var maliciousCronNames = []string{
	"systemd-timers", "systemd-boot", "systemd-boot-early", ".systemd-update-notifier",
}

var maliciousUnitNames = []string{
	"systemd-resolved-cache", "systemd-networkd-helper", "systemd-timesyncd-update",
	"dbus-system-helper", "systemd-journald-cache", "myservices", "service-manager",
	"daemon-helper", "system-monitor", "service-controller", "update-daemon", "background-service",
}

var unitContentMarkers = []string{
	"systemd-resolved-helper", "systemd-networkd-helper", "systemd-timesyncd-helper",
	"dbus-system-helper", "systemd-journald-helper", ".system-service", "cache-service",
	"/var/tmp/876c7af6", "01b51ec6",
}

var rcLineMarkers = []string{
	"system-service", "cache-service", "876c7af6", "01b51ec6", "libnss_ninel", "libnss_cache",
}

// 攻击者 SSH 公钥指纹（SHA256，ssh-keygen 格式）
const attackerFP = "SHA256:AkrAM6Cdbkqok1OHU527WzpYGQqPQJrubcEP9Dlj7yI"
const attackerComment = "ElPatrono1337"

// ---------------------------------------------------------------- 结构

// 疫苗目录：由本工具故意创建并加不可变属性的"占位陷阱"，
// 目的是让木马无法在这些路径上创建文件。带标记文件者一律不算感染。
func isVaccine(p string) bool {
	p = rp(p)
	fi, err := os.Lstat(p)
	if err != nil || !fi.IsDir() {
		return false
	}
	_, err2 := os.Lstat(p + "/.rkk-vaccine")
	return err2 == nil
}

type Finding struct {
	Kind   string // FILE / CONFIG / PROCESS / ACCOUNT / KEY / UNIT
	Target string
	Detail string
}

type Cleaner struct {
	BackupDir string
	Log       []string
	Changed   int
	Failed    int
	aggr      bool
	quiet     bool // 守护模式：不打印，只记日志
}

func (c *Cleaner) note(f string, a ...any) {
	line := fmt.Sprintf(f, a...)
	if rootDir != "" {
		line = strings.ReplaceAll(line, rootDir, "")
	}
	if c.quiet {
		c.Log = append(c.Log, line)
		return
	}
	c.Log = append(c.Log, line)
	fmt.Println("   " + line)
}

// ---------------------------------------------------------------- 内存/工具

func fileExists(p string) bool {
	_, err := os.Lstat(rp(p))
	return err == nil
}

func readSmall(p string, limit int64) string {
	f, err := os.Open(rp(p))
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 0, 4096)
	r := io.LimitReader(f, limit)
	b, err := io.ReadAll(r)
	if err != nil {
		return string(buf)
	}
	return string(b)
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// 计算 SSH 公钥指纹：base64(sha256(blob))，与 ssh-keygen -lf 输出一致
func keyFingerprint(line string) string {
	for _, f := range strings.Fields(line) {
		if len(f) < 60 || !strings.HasPrefix(f, "AAAA") {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(f)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(blob)
		return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	}
	return ""
}

// ---------------------------------------------------------------- 进程扫描

type procInfo struct {
	PID     int
	Comm    string
	Cmdline string
	Exe     string
	Env     string
	Maps    string
}

func readProc(p string, what string) string {
	b := readSmall(p, 1<<20)
	return strings.ReplaceAll(string(b), "\x00", " ")
}

func scanProcs() []procInfo {
	if rootDir != "" {
		return nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	self := os.Getpid()
	var out []procInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self || pid == 1 {
			continue
		}
		base := "/proc/" + e.Name()
		comm := strings.TrimSpace(readSmall(base+"/comm", 512))
		cmdline := strings.TrimSpace(readProc(base+"/cmdline", "cmdline"))
		exe, _ := os.Readlink(base + "/exe")
		env := readProc(base+"/environ", "environ")
		maps := readProc(base+"/maps", "maps")
		out = append(out, procInfo{pid, comm, cmdline, exe, env, maps})
	}
	return out
}

func (p procInfo) match() (bool, string) {
	if p.PID == os.Getpid() || p.Comm == "rkk" || p.Comm == "rkk" {
		return false, ""
	}
	hay := p.Comm + " " + p.Cmdline + " " + p.Exe + " " + p.Maps
	if containsAny(hay, procKeywords...) {
		return true, "进程名/命令行/加载库命中"
	}
	if containsAny(p.Env, envMarkers...) {
		return true, "进程环境变量含木马标记"
	}
	return false, ""
}

func killPIDs(pids []int) {
	for _, pid := range pids {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// ---------------------------------------------------------------- 文件操作

const (
	fsIOCGetFlags = 0x80086601
	fsIOCSetFlags = 0x40086602
	fsImmutable   = 0x00000010
	fsAppend      = 0x00000020
)

// 清除 chattr +i / +a 属性：绕过已被替换的 chattr 命令
func clearImmutable(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	var flags int32
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIOCGetFlags, uintptr(unsafe.Pointer(&flags)))
	if flags&(fsImmutable|fsAppend) == 0 {
		return
	}
	flags &^= fsImmutable | fsAppend
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIOCSetFlags, uintptr(unsafe.Pointer(&flags)))
}

func forceRemove(p string) error {
	p = rp(p)
	fi, err := os.Lstat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.IsDir() {
		_ = filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
			if err == nil && info != nil && !info.IsDir() {
				clearImmutable(path)
			}
			return nil
		})
		return os.RemoveAll(p)
	}
	clearImmutable(p)
	if err := os.Remove(p); err != nil {
		clearImmutable(p)
		return os.Remove(p)
	}
	return nil
}

func (c *Cleaner) backup(p string) {
	logical := p
	if rootDir != "" {
		logical = strings.TrimPrefix(logical, rootDir)
	}
	rel := strings.TrimPrefix(logical, "/")
	rel = strings.ReplaceAll(rel, "/", "_")
	dst := filepath.Join(c.BackupDir, rel)
	fi, err := os.Lstat(rp(p))
	if err != nil {
		return
	}
	if fi.IsDir() {
		_ = os.MkdirAll(dst, 0700)
		var total int64
		_ = filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			if total > 32<<20 {
				return nil
			}
			if info.Size() > 8<<20 {
				h, _ := sha256File(path)
				_ = os.WriteFile(filepath.Join(dst, filepath.Base(path)+".sha256"), []byte(fmt.Sprintf("SKIP(too large, not copied)  size=%d  sha256=%s  %s\n", info.Size(), h, path)), 0600)
				return nil
			}
			total += info.Size()
			_ = copyFile(path, filepath.Join(dst, strings.ReplaceAll(strings.TrimPrefix(path, rp(p)+"/"), "/", "_")), info.Mode())
			return nil
		})
		return
	}
	if fi.Size() > 8<<20 {
		h, _ := sha256File(rp(p))
		_ = os.WriteFile(dst+".sha256", []byte(fmt.Sprintf("SKIP(too large, not copied)  size=%d  sha256=%s  %s\n", fi.Size(), h, p)), 0600)
		return
	}
	_ = copyFile(rp(p), dst, fi.Mode())
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	_ = os.MkdirAll(filepath.Dir(dst), 0700)
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func writeAtomic(p string, content string, mode os.FileMode) error {
	p = rp(p)
	clearImmutable(p)
	tmp := p + ".rkk-tmp"
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func runCmd(timeout time.Duration, name string, args ...string) (string, error) {
	if rootDir != "" {
		return "", fmt.Errorf("offline mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ---------------------------------------------------------------- 扫描

func doScan() []Finding {
	var fs []Finding

	add := func(kind, target, detail string) {
		if rootDir != "" {
			target = strings.TrimPrefix(target, rootDir)
			if target == "" {
				target = "/"
			}
		}
		fs = append(fs, Finding{kind, target, detail})
	}

	// 1) 落点文件
	for _, p := range payloadPaths {
		if fileExists(p) && !isVaccine(p) {
			add("FILE", p, "恶意载荷/隐藏库/后门模块")
		}
	}
	// 2) glob
	for _, g := range payloadGlobs {
		matches, _ := glob(g)
		for _, m := range matches {
			if fileExists(m) && !isVaccine(m) {
				add("FILE", m, "恶意载荷残留")
			}
		}
	}
	// 3) 伪装目录
	for _, d := range decoyDirs {
		if fileExists(d) && !isVaccine(d) {
			add("FILE", d, "木马自建的伪装目录")
		}
	}

	// 4) ld.so.preload
	if s := readSmall("/etc/ld.so.preload", 4096); s != "" {
		if containsAny(s, "libnss_cache", "libnss_ninel", "hider", "/dev/shm/", "/tmp/.") {
			add("CONFIG", "/etc/ld.so.preload", "全局注入恶意库："+strings.TrimSpace(s))
		}
	}

	// 5) nsswitch
	if s := readSmall("/etc/nsswitch.conf", 8192); strings.Contains(s, "ninel") {
		add("CONFIG", "/etc/nsswitch.conf", "passwd/shadow/group 被插入 ninel 模块")
	}

	// 6) PAM
	pamFiles, _ := glob("/etc/pam.d/*")
	for _, f := range pamFiles {
		if strings.Contains(readSmall(f, 1<<20), "pam_master") {
			add("CONFIG", f, "PAM 栈植入 pam_master.so（万能密码后门）")
		}
	}

	// 7) sshd
	if s := readSmall("/etc/ssh/sshd_config", 1<<20); s != "" {
		if containsAny(s, "Match User ninel", "updates-20260202") || strings.Contains(s, "StrictModes no") {
			add("CONFIG", "/etc/ssh/sshd_config", "存在后门 Match 块 / 隐藏 AuthorizedKeysFile / StrictModes no")
		}
	}

	// 8) authorized_keys
	keyFiles, _ := glob("/root/.ssh/authorized_keys")
	keyFiles2, _ := glob("/home/*/.ssh/authorized_keys")
	keyFiles = append(keyFiles, keyFiles2...)
	for _, f := range keyFiles {
		content := readSmall(f, 1<<20)
		sc := bufio.NewScanner(strings.NewReader(content))
		for sc.Scan() {
			line := sc.Text()
			if strings.Contains(line, attackerComment) || keyFingerprint(line) == attackerFP {
				add("KEY", f, "攻击者公钥（指纹 "+attackerFP+"）")
				break
			}
		}
	}

	// 9) 账户 / sudoers
	if s := readSmall("/etc/passwd", 1<<20); strings.Contains(s, "\nninel:") || strings.HasPrefix(s, "ninel:") {
		add("ACCOUNT", "/etc/passwd", "存在后门账户 ninel")
	}
	if s := readSmall("/etc/passwd", 1<<20); strings.Contains(s, "\nnode:") || strings.HasPrefix(s, "node:") {
		add("ACCOUNT", "/etc/passwd", "存在可疑账户 node（如非业务账号请一并删除）")
	}
	sd, _ := glob("/etc/sudoers.d/*")
	for _, f := range sd {
		if strings.Contains(readSmall(f, 1<<20), "NOPASSWD") {
			add("CONFIG", f, "免密 root 授权")
		}
	}

	// 10) cron
	cd, _ := glob("/etc/cron.d/*")
	for _, f := range cd {
		if isVaccine(f) {
			continue
		}
		base := filepath.Base(f)
		content := readSmall(f, 1<<20)
		if containsAny(base, maliciousCronNames...) || containsAny(content, "system-service", "876c7af6", "01b51ec6") {
			add("CONFIG", f, "恶意 cron 持久化")
		}
	}
	if s := readSmall("/var/spool/cron/crontabs/root", 1<<20); containsAny(s, "system-service", "876c7af6", "01b51ec6") {
		add("CONFIG", "/var/spool/cron/crontabs/root", "root crontab 含恶意任务")
	}

	// 11) systemd
	for _, dir := range []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"} {
		fs2, _ := glob(dir + "/*")
		for _, f := range fs2 {
			if isVaccine(f) {
				continue
			}
			base := strings.TrimSuffix(filepath.Base(f), ".service")
			if containsAny(base, maliciousUnitNames...) {
				add("UNIT", f, "伪造的 systemd 服务")
				continue
			}
			if !strings.HasSuffix(f, ".service") {
				continue
			}
			if containsAny(readSmall(f, 1<<20), unitContentMarkers...) {
				add("UNIT", f, "服务内容指向木马载荷")
			}
		}
	}
	for _, g := range []string{"/etc/systemd/system-generators/*", "/usr/local/lib/systemd/system-generators/*", "/lib/systemd/system-generators/*"} {
		matches, _ := glob(g)
		for _, m := range matches {
			if strings.Contains(filepath.Base(m), "system-service") || strings.Contains(filepath.Base(m), "update-checker") {
				add("UNIT", m, "systemd generator 持久化")
			}
		}
	}

	// 12) initramfs
	for _, h := range []string{"/etc/initramfs-tools/hooks/zz-system-service", "/usr/share/initramfs-tools/hooks/zz-system-service"} {
		if fileExists(h) && !isVaccine(h) {
			add("CONFIG", h, "initramfs hook（急救模式也会拉起）")
		}
	}

	// 13) rc.local / shell rc
	for _, f := range append([]string{"/etc/rc.local"}, rcFiles()...) {
		if !fileExists(f) {
			continue
		}
		if containsAny(readSmall(f, 1<<20), rcLineMarkers...) {
			add("CONFIG", f, "启动脚本被植入木马拉起命令")
		}
	}

	// 14) 进程
	for _, p := range scanProcs() {
		if ok, why := p.match(); ok {
			add("PROCESS", fmt.Sprintf("PID %d (%s)", p.PID, p.Comm), why+" | exe="+p.Exe)
		}
	}

	return fs
}

func rcFiles() []string {
	base := []string{"/root/.bashrc", "/root/.profile", "/root/.bash_profile", "/root/.zshrc"}
	homes, _ := glob("/home/*")
	for _, h := range homes {
		for _, n := range []string{".bashrc", ".profile", ".bash_profile", ".zshrc"} {
			base = append(base, filepath.Join(h, n))
		}
	}
	return base
}

// ---------------------------------------------------------------- 清除

func doClean(aggr bool) {
	ts := time.Now().Format("20060102-150405")
	dir := "/var/backups/rootkit-killer-" + ts
	if err := os.MkdirAll(rp(dir), 0700); err != nil {
		dir = "/root/rootkit-killer-" + ts
		_ = os.MkdirAll(rp(dir), 0700)
	}
	c := &Cleaner{BackupDir: rp(dir), aggr: aggr}
	fmt.Printf("备份目录：%s\n", dir)

	// ---- 1. 先断持久化（否则 systemd Restart=always / cron 会立刻把进程拉回来）
	fmt.Println("\n[1/9] 移除持久化配置（cron / systemd / initramfs / rc）")
	c.cleanCron()
	c.cleanSystemd()
	c.cleanInitramfs()
	c.cleanRc()

	// ---- 2. 结束恶意进程（多轮，防止看门狗互拉）
	fmt.Println("\n[2/9] 结束恶意进程")
	for round := 0; round < 4; round++ {
		var pids []int
		for _, p := range scanProcs() {
			if ok, _ := p.match(); ok {
				pids = append(pids, p.PID)
			}
		}
		if len(pids) == 0 {
			if round == 0 {
				c.note("未发现运行中的恶意进程")
			}
			break
		}
		c.note("第 %d 轮：命中 %d 个进程 %v", round+1, len(pids), pids)
		killPIDs(pids)
		time.Sleep(300 * time.Millisecond)
	}

	// ---- 3. 关闭全局 preload
	fmt.Println("\n[3/9] 解除 /etc/ld.so.preload 全局注入")
	c.cleanPreload()

	// ---- 4. NSS
	fmt.Println("\n[4/9] 修复 /etc/nsswitch.conf")
	c.cleanNsswitch()

	// ---- 5. PAM
	fmt.Println("\n[5/9] 摘除 PAM 后门")
	c.cleanPam()

	// ---- 6. SSH
	fmt.Println("\n[6/9] 清理 SSH 后门")
	c.cleanSSH()

	// ---- 7. 账户与 sudo
	fmt.Println("\n[7/9] 清理后门账户与 sudoers")
	c.cleanAccounts()

	// ---- 8. 载荷文件
	fmt.Println("\n[8/9] 删除载荷 / 隐藏库 / 伪装目录")
	c.cleanPayloads()

	// ---- 9. 复检
	fmt.Println("\n[9/9] 复检")
	left := doScan()
	if len(left) == 0 {
		c.note("复检通过：未发现残留")
	} else {
		fmt.Printf("   仍有 %d 项残留：\n", len(left))
		for _, f := range left {
			fmt.Printf("     - [%s] %s | %s\n", f.Kind, f.Target, f.Detail)
		}
	}

	// 备份清单
	_ = os.WriteFile(filepath.Join(dir, "actions.log"), []byte(strings.Join(c.Log, "\n")), 0600)

	fmt.Printf("\n完成：变更 %d 项，失败 %d 项。日志：%s/actions.log\n", c.Changed, c.Failed, dir)
	fmt.Println("建议：重启后再执行一次 ./rkk 确认清零；若仍有残留，进救援/单用户模式再跑。")
}

func (c *Cleaner) removed(p, why string) {
	if !fileExists(p) {
		return
	}
	c.backup(p)
	if err := forceRemove(p); err != nil {
		c.Failed++
		c.note("[FAIL] 删除 %s 失败：%v", p, err)
		return
	}
	c.Changed++
	c.note("[OK] 已隔离 %s（%s）", p, why)
}

func (c *Cleaner) cleanCron() {
	for _, n := range maliciousCronNames {
		if isVaccine("/etc/cron.d/" + n) {
			// 占位陷阱：这是本工具故意放的，跳过
			if rootDir == "" {
				_, _ = runCmd(20*time.Second, "systemctl", "stop", n+".service")
			}
			continue
		}
		c.removed("/etc/cron.d/"+n, "恶意 cron")
	}
	cd, _ := glob("/etc/cron.d/*")
	for _, f := range cd {
		if isVaccine(f) {
			continue
		}
		if containsAny(readSmall(f, 1<<20), "system-service", "876c7af6", "01b51ec6") {
			c.removed(f, "cron 内容命中")
		}
	}
	// root 及其他用户 crontab
	crontabs, _ := glob("/var/spool/cron/crontabs/*")
	for _, f := range crontabs {
		s := readSmall(f, 1<<20)
		if !containsAny(s, "system-service", "876c7af6", "01b51ec6") {
			continue
		}
		c.backup(f)
		var keep []string
		for _, line := range strings.Split(s, "\n") {
			if containsAny(line, "system-service", "876c7af6", "01b51ec6") {
				continue
			}
			keep = append(keep, line)
		}
		fi, _ := os.Stat(f)
		mode := os.FileMode(0600)
		if fi != nil {
			mode = fi.Mode()
		}
		if err := writeAtomic(f, strings.TrimRight(strings.Join(keep, "\n"), "\n")+"\n", mode); err != nil {
			c.Failed++
			c.note("[FAIL] 写入 %s 失败：%v", f, err)
		} else {
			c.Changed++
			c.note("[OK] 已清理 %s 中的恶意任务", f)
		}
	}
	// /etc/crontab
	if f := "/etc/crontab"; fileExists(f) {
		s := readSmall(f, 1<<20)
		if containsAny(s, "system-service", "876c7af6", "01b51ec6") {
			c.backup(f)
			var keep []string
			for _, line := range strings.Split(s, "\n") {
				if containsAny(line, "system-service", "876c7af6", "01b51ec6") {
					continue
				}
				keep = append(keep, line)
			}
			if err := writeAtomic(f, strings.Join(keep, "\n"), 0644); err == nil {
				c.Changed++
				c.note("[OK] 已清理 /etc/crontab")
			}
		}
	}
}

func (c *Cleaner) cleanSystemd() {
	for _, n := range maliciousUnitNames {
		if rootDir == "" {
			_, _ = runCmd(20*time.Second, "systemctl", "stop", n+".service")
			if n == "myservices" {
				_, _ = runCmd(20*time.Second, "systemctl", "stop", "myservices.target")
			}
			_, _ = runCmd(20*time.Second, "systemctl", "disable", n+".service")
		}
		for _, dir := range []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"} {
			u := filepath.Join(dir, n+".service")
			if isVaccine(u) {
				continue
			}
			c.removed(u, "伪造的 systemd 服务")
		}
		// wants 软链
		links, _ := glob("/etc/systemd/system/*.wants/" + n + ".service")
		for _, l := range links {
			c.removed(l, "unit 软链")
		}
	}
	for _, dir := range []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"} {
		files, _ := glob(dir + "/*.service")
		for _, f := range files {
			if containsAny(readSmall(f, 1<<20), unitContentMarkers...) {
				c.removed(f, "服务内容指向木马载荷")
			}
		}
	}
	for _, g := range []string{
		"/etc/systemd/system-generators/system-service-generator",
		"/etc/systemd/system-generators/update-checker",
		"/usr/local/lib/systemd/system-generators/system-service-generator",
		"/usr/local/lib/systemd/system-generators/update-checker",
		"/lib/systemd/system-generators/system-service-generator",
	} {
		c.removed(g, "systemd generator 持久化")
	}
	if rootDir == "" {
		if _, err := runCmd(30*time.Second, "systemctl", "daemon-reload"); err != nil {
			c.note("[warn] systemctl daemon-reload 未成功（可能已被替换/不可用），重启后生效")
		}
	}
}

func (c *Cleaner) cleanInitramfs() {
	for _, h := range []string{
		"/etc/initramfs-tools/hooks/zz-system-service",
		"/usr/share/initramfs-tools/hooks/zz-system-service",
	} {
		c.removed(h, "initramfs hook")
	}
	if fileExists("/usr/sbin/update-initramfs") || fileExists("/usr/sbin/update-initramfs.real") {
		out, err := runCmd(180*time.Second, "update-initramfs", "-u", "-k", "all")
		if err != nil {
			c.note("[warn] update-initramfs 失败：%v %s", err, out)
		} else {
			c.note("[OK] 已重建 initramfs")
		}
	}
}

func (c *Cleaner) cleanRc() {
	files := append([]string{"/etc/rc.local"}, rcFiles()...)
	for _, f := range files {
		if !fileExists(f) {
			continue
		}
		s := readSmall(f, 1<<20)
		if !containsAny(s, rcLineMarkers...) {
			continue
		}
		c.backup(f)
		var keep []string
		for _, line := range strings.Split(s, "\n") {
			if containsAny(line, rcLineMarkers...) && (strings.Contains(line, "/") || strings.Contains(line, "=")) {
				continue
			}
			keep = append(keep, line)
		}
		fi, _ := os.Stat(f)
		mode := os.FileMode(0644)
		if fi != nil {
			mode = fi.Mode()
		}
		if err := writeAtomic(f, strings.Join(keep, "\n"), mode); err != nil {
			c.Failed++
			c.note("[FAIL] 写入 %s 失败：%v", f, err)
		} else {
			c.Changed++
			c.note("[OK] 已清理启动脚本 %s", f)
		}
	}
}

func (c *Cleaner) cleanPreload() {
	f := "/etc/ld.so.preload"
	s := readSmall(f, 4096)
	if s == "" {
		c.note("无 /etc/ld.so.preload，跳过")
		return
	}
	c.backup(f)
	var keep []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if containsAny(line, "libnss_cache", "libnss_ninel", "hider", "/dev/shm/", "/tmp/.") {
			continue
		}
		keep = append(keep, line)
	}
	if len(keep) == 0 {
		if err := forceRemove(f); err != nil {
			c.Failed++
			c.note("[FAIL] 删除 /etc/ld.so.preload 失败：%v", err)
		} else {
			c.Changed++
			c.note("[OK] 已删除 /etc/ld.so.preload（其中全部为恶意行）")
		}
		return
	}
	if err := writeAtomic(f, strings.Join(keep, "\n")+"\n", 0644); err != nil {
		c.Failed++
		c.note("[FAIL] 写入 /etc/ld.so.preload 失败：%v", err)
	} else {
		c.Changed++
		c.note("[OK] 已从 /etc/ld.so.preload 移除恶意行（保留 %d 行自定义配置）", len(keep))
	}
}

func (c *Cleaner) cleanNsswitch() {
	f := "/etc/nsswitch.conf"
	s := readSmall(f, 8192)
	if !strings.Contains(s, "ninel") {
		c.note("nsswitch.conf 无 ninel，跳过")
		return
	}
	c.backup(f)
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(line, "passwd:") && !strings.HasPrefix(line, "shadow:") && !strings.HasPrefix(line, "group:") {
			out = append(out, line)
			continue
		}
		fields := strings.Fields(line)
		var keepFields []string
		for i, fld := range fields {
			if i > 0 && fld == "ninel" {
				continue
			}
			keepFields = append(keepFields, fld)
		}
		out = append(out, strings.Join(keepFields, " "))
	}
	if err := writeAtomic(f, strings.Join(out, "\n"), 0644); err != nil {
		c.Failed++
		c.note("[FAIL] 写入 nsswitch.conf 失败：%v", err)
	} else {
		c.Changed++
		c.note("[OK] 已移除 nsswitch.conf 中的 ninel")
	}
	// 删除 ninel 库
	for _, p := range payloadPaths {
		if strings.Contains(p, "libnss_ninel") {
			c.removed(p, "NSS 伪装模块")
		}
	}
}

func (c *Cleaner) cleanPam() {
	pamFiles, _ := glob("/etc/pam.d/*")
	for _, f := range pamFiles {
		s := readSmall(f, 1<<20)
		if !strings.Contains(s, "pam_master") {
			continue
		}
		c.backup(f)
		// 优先从木马自己留下的备份还原（那是被修改之前的原件）
		bak := f + ".pm-bak"
		if fileExists(bak) {
			if data, err := os.ReadFile(rp(bak)); err == nil && !strings.Contains(string(data), "pam_master") {
				fi, _ := os.Stat(f)
				mode := os.FileMode(0644)
				if fi != nil {
					mode = fi.Mode()
				}
				if err := writeAtomic(f, string(data), mode); err == nil {
					c.Changed++
					c.note("[OK] 已从 %s 还原 %s", bak, f)
					c.backup(bak)
					_ = forceRemove(bak)
					continue
				}
			}
		}
		var keep []string
		for _, line := range strings.Split(s, "\n") {
			if strings.Contains(line, "pam_master") {
				continue
			}
			keep = append(keep, line)
		}
		fi, _ := os.Stat(f)
		mode := os.FileMode(0644)
		if fi != nil {
			mode = fi.Mode()
		}
		if err := writeAtomic(f, strings.Join(keep, "\n"), mode); err != nil {
			c.Failed++
			c.note("[FAIL] 写入 %s 失败：%v", f, err)
		} else {
			c.Changed++
			c.note("[OK] 已从 %s 删除 pam_master 行", f)
		}
	}
	// 删除模块本体与 /etc/.pm
	for _, p := range payloadPaths {
		if strings.Contains(p, "pam_master") || p == "/etc/.pm" {
			c.removed(p, "PAM 后门模块/口令文件")
		}
	}
	// 清理 authselect 自定义 profile（RHEL）
	c.removed("/etc/authselect/custom/pam_master", "authselect 后门 profile")

	if fileExists("/usr/sbin/pam-auth-update") || fileExists("/usr/sbin/pam-auth-update.real") {
		out, err := runCmd(60*time.Second, "pam-auth-update", "--force")
		if err != nil {
			c.note("[warn] pam-auth-update 未成功：%v %s", err, out)
		} else {
			c.note("[OK] 已重建 PAM 配置")
		}
	}
}

func (c *Cleaner) cleanSSH() {
	f := "/etc/ssh/sshd_config"
	if fileExists(f) {
		s := readSmall(f, 1<<20)
		if containsAny(s, "Match User ninel", "updates-20260202") || strings.Contains(s, "StrictModes no") {
			c.backup(f)
			if fileExists(f+".pm-bak") {
				if data, err := os.ReadFile(rp(f + ".pm-bak")); err == nil && !containsAny(string(data), "Match User ninel", "updates-20260202", "StrictModes no") {
					if err := writeAtomic(f, string(data), 0644); err == nil {
						c.Changed++
						c.note("[OK] 已从 sshd_config.pm-bak 还原 sshd_config")
						_ = forceRemove(f + ".pm-bak")
					}
				}
			} else {
				var keep []string
				inMatch := false
				for _, line := range strings.Split(s, "\n") {
					trim := strings.TrimSpace(line)
					if inMatch {
						// 块结束：空行，或出现顶层指令
						if trim == "" {
							inMatch = false
							continue
						}
						if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
							continue
						}
						inMatch = false
					}
					if strings.HasPrefix(trim, "Match ") && (strings.Contains(trim, "ninel") || strings.Contains(trim, "updates-")) {
						inMatch = true
						continue
					}
					if strings.HasPrefix(trim, "StrictModes no") {
						continue
					}
					keep = append(keep, line)
				}
				if err := writeAtomic(f, strings.Join(keep, "\n"), 0644); err != nil {
					c.Failed++
					c.note("[FAIL] 写入 sshd_config 失败：%v", err)
				} else {
					c.Changed++
					c.note("[OK] 已移除 sshd_config 中的后门块与 StrictModes no")
				}
			}
		} else {
			c.note("sshd_config 未见后门配置")
		}
	}

	keyFiles := []string{"/root/.ssh/authorized_keys"}
	if m, _ := glob("/home/*/.ssh/authorized_keys"); m != nil {
		keyFiles = append(keyFiles, m...)
	}
	for _, kf := range keyFiles {
		s := readSmall(kf, 1<<20)
		if s == "" {
			continue
		}
		c.backup(kf)
		var keep []string
		hit := false
		for _, line := range strings.Split(s, "\n") {
			if strings.Contains(line, attackerComment) || keyFingerprint(line) == attackerFP {
				hit = true
				continue
			}
			keep = append(keep, line)
		}
		if !hit {
			continue
		}
		content := strings.TrimRight(strings.Join(keep, "\n"), "\n")
		if content != "" {
			content += "\n"
		}
		fi, _ := os.Stat(kf)
		mode := os.FileMode(0600)
		if fi != nil {
			mode = fi.Mode()
		}
		if err := writeAtomic(kf, content, mode); err != nil {
			c.Failed++
			c.note("[FAIL] 写入 %s 失败：%v", kf, err)
		} else {
			c.Changed++
			c.note("[OK] 已从 %s 移除攻击者公钥", kf)
		}
	}

	// 隐藏的 AuthorizedKeysFile 文件本体
	c.removed("/var/tmp/updates-20260202", "隐藏的 SSH 授权文件")

	if _, err := runCmd(20*time.Second, "sshd", "-t"); err != nil && rootDir == "" {
		c.note("[warn] sshd -t 校验未通过，请手工检查 /etc/ssh/sshd_config")
	}
}

func (c *Cleaner) cleanAccounts() {
	// passwd/shadow/group/gshadow
	for _, f := range []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"} {
		s := readSmall(f, 1<<20)
		if s == "" {
			continue
		}
		var keep []string
		hit := false
		names := []string{"ninel"}
		if c.aggr {
			names = append(names, "node")
		}
		for _, line := range strings.Split(s, "\n") {
			user := strings.SplitN(line, ":", 2)[0]
			bad := false
			for _, n := range names {
				if user == n {
					bad = true
				}
			}
			if bad {
				hit = true
				continue
			}
			// group 成员列表里的 ninel
			if f == "/etc/group" || f == "/etc/gshadow" {
				parts := strings.Split(line, ":")
				if len(parts) >= 4 && strings.Contains(parts[3], "ninel") {
					var members []string
					for _, m := range strings.Split(parts[3], ",") {
						if m == "ninel" || m == "" {
							continue
						}
						members = append(members, m)
					}
					parts[3] = strings.Join(members, ",")
					line = strings.Join(parts, ":")
					hit = true
				}
			}
			keep = append(keep, line)
		}
		if !hit {
			continue
		}
		c.backup(f)
		fi, _ := os.Stat(f)
		mode := os.FileMode(0644)
		if fi != nil {
			mode = fi.Mode()
		}
		if err := writeAtomic(f, strings.Join(keep, "\n"), mode); err != nil {
			c.Failed++
			c.note("[FAIL] 写入 %s 失败：%v", f, err)
		} else {
			c.Changed++
			c.note("[OK] 已从 %s 移除后门账户", f)
		}
	}

	// sudoers.d
	c.removed("/etc/sudoers.d/99-ninel-root", "免密 root 授权")
	if c.aggr {
		c.removed("/etc/sudoers.d/node", "免密 root 授权")
	} else if fileExists("/etc/sudoers.d/node") {
		c.note("[warn] 存在 /etc/sudoers.d/node（node 免密 root），若非业务账号请加 -aggressive 或手工删除")
	}
	if fs, _ := glob("/etc/sudoers.d/*"); fs != nil {
		for _, f := range fs {
			s := readSmall(f, 1<<20)
			if strings.Contains(s, "ninel") {
				c.removed(f, "sudoers 含 ninel")
			}
		}
	}
	if _, err := runCmd(20*time.Second, "visudo", "-c"); err != nil && rootDir == "" {
		c.note("[warn] visudo -c 未通过，请手工检查 sudoers")
	}
}

func (c *Cleaner) cleanPayloads() {
	for _, p := range payloadPaths {
		if p == "/etc/.pm" || strings.Contains(p, "pam_master") || strings.Contains(p, "libnss_ninel") {
			continue // 已在前面处理
		}
		if isVaccine(p) {
			continue // 疫苗占位，保留
		}
		c.removed(p, "恶意载荷")
	}
	for _, g := range payloadGlobs {
		matches, _ := glob(g)
		for _, m := range matches {
			if isVaccine(m) {
				continue
			}
			c.removed(m, "载荷残留")
		}
	}
	for _, d := range decoyDirs {
		if fileExists(d) && !isVaccine(d) {
			c.removed(d, "伪装目录")
		}
	}
	// 被替换的核心命令：检测 UPX 壳并给出修复命令
	for _, b := range []string{"/usr/bin/rm", "/usr/bin/kill", "/usr/bin/chattr", "/usr/bin/passwd", "/usr/bin/chpasswd", "/usr/sbin/kill", "/usr/sbin/chattr"} {
		if !fileExists(b) {
			continue
		}
		if strings.Contains(readSmall(b, 4096), "UPX!") {
			c.note("[warn] %s 被 UPX 加壳（疑似木马替换版），请执行：apt-get install --reinstall -y coreutils passwd util-linux", b)
		}
	}
	c.note("提示：/dev/shm/.orig_* 是被木马替换后的副本，不是原始命令，切勿用于恢复")
}

// ---------------------------------------------------------------- 入口

