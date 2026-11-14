// rkk —— 针对 child.malware / ninel / pam_master 家族的"免疫 + 监控 + 自动清除"守护程序
//
// 用法：
//   rkk                   扫描（只读）
//   rkk clean -yes        清除一次
//   rkk install           安装守护（布防 + 常驻 + 自愈）
//   rkk run              前台运行守护（systemd 调用）
//   rkk status            查看状态
//   rkk immunize          只布防，不常驻
//   rkk uninstall         卸载并解除全部锁定
//
// 全静态编译，不经过 ld.so / libc，因此不受目标机 /etc/ld.so.preload 钩子影响。
package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

func usage() {
	fmt.Printf(`rkk v%s —— 免疫 / 监控 / 自动清除（child.malware 家族）

  rkk                          只读扫描当前主机
  rkk clean [-yes] [-aggressive]  清除一次（-yes 免二次确认）
  rkk install [-yes] [-aggressive] 安装守护：布防 + 常驻巡检 + 自愈
  rkk run                      前台运行守护（由 systemd 启动）
  rkk status                   状态、布防点数量、最近日志
  rkk immunize                 只布防（预置不可变占位、锁定 ld.so.preload）
  rkk uninstall                卸载守护并解除全部锁定

环境变量：
  RKK_ROOT=/挂载点                    对离线镜像操作（救援/取证）
`, version)
}

func main() {
	args := os.Args[1:]
	cmd := "scan"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	} else if len(args) > 0 {
		// 兼容旧版 rkk 的 flag 风格：-clean / -yes / -aggressive
		for _, a := range args {
			if a == "-clean" {
				cmd = "clean"
			}
		}
	}

	switch cmd {
	case "scan":
		cmdScan(args)
	case "clean":
		cmdClean(args)
	case "install":
		cmdInstall(args)
	case "run":
		cmdRun(args)
	case "patrol":
		cmdPatrol(args)
	case "status":
		cmdStatus(args)
	case "immunize":
		cmdImmunize(args)
	case "uninstall":
		cmdUninstall(args)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Printf("未知子命令：%s\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func cmdScan(args []string) {
	fmt.Printf("rkk v%s（静态编译，不受 LD_PRELOAD 钩子影响）\n", version)
	fs := doScan()
	if len(fs) == 0 {
		n := vaccineCount()
		if n > 0 {
			fmt.Printf("未发现匹配特征。（已布防 %d 处）\n", n)
		} else {
			fmt.Println("未发现匹配特征。")
		}
		fmt.Println("提示：本工具只识别已知的 child.malware/ninel/pam_master 家族特征；")
		fmt.Println("      如仍有异常（CPU/网络/登录记录缺失），建议直接重建系统。")
		return
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Kind != fs[j].Kind {
			return fs[i].Kind < fs[j].Kind
		}
		return fs[i].Target < fs[j].Target
	})
	fmt.Printf("\n发现 %d 项疑似感染痕迹：\n\n", len(fs))
	for i, f := range fs {
		fmt.Printf("%3d. [%-7s] %s\n      %s\n", i+1, f.Kind, f.Target, f.Detail)
	}
	fmt.Println("\n当前为只读扫描模式。清除请执行：rkk clean -yes")
	fmt.Println("要长期免疫请执行：rkk install")
	os.Exit(1)
}

func cmdClean(args []string) {
	yes := hasFlag(args, "-yes") || hasFlag(args, "-y")
	aggr := hasFlag(args, "-aggressive")
	fmt.Printf("rkk v%s（静态编译，不受 LD_PRELOAD 钩子影响）\n", version)

	if os.Geteuid() != 0 && rootDir == "" {
		fmt.Println("错误：清除操作需要 root")
		os.Exit(2)
	}

	findings := doScan()
	if len(findings) == 0 {
		fmt.Println("未发现匹配特征。")
		return
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Kind != findings[j].Kind {
			return findings[i].Kind < findings[j].Kind
		}
		return findings[i].Target < findings[j].Target
	})
	fmt.Printf("\n发现 %d 项疑似感染痕迹：\n\n", len(findings))
	for i, f := range findings {
		fmt.Printf("%3d. [%-7s] %s\n      %s\n", i+1, f.Kind, f.Target, f.Detail)
	}
	if !yes {
		fmt.Print("\n即将修改系统（会先备份）。输入 yes 继续：")
		var in string
		fmt.Scanln(&in)
		if strings.TrimSpace(strings.ToLower(in)) != "yes" {
			fmt.Println("已取消。")
			return
		}
	}
	doClean(aggr)
}
