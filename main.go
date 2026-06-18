// Command ipcheck は IP アドレスが CIDR の集合に含まれるかを判定する CLI。
//
// 使い方:
//
//	ipcheck -cidr 10.0.0.0/8,192.168.0.0/16 1.2.3.4 10.1.2.3
//	ipcheck -file cidrs.txt 10.1.2.3
//	echo "10.1.2.3" | ipcheck -file cidrs.txt
//
// 終了ステータス: 判定した全 IP がいずれかの CIDR に一致したら 0、
// 1 つでも不一致なら 1、引数やパースのエラーは 2。
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"ipcheck/cidrcheck"
)

const (
	ansiYellow = "\033[33m"
	ansiReset  = "\033[0m"
)

func main() {
	var (
		cidrList = flag.String("cidr", "", "カンマ区切りの CIDR（例: 10.0.0.0/8,192.168.0.0/16）")
		cidrFile = flag.String("file", "", "CIDR ファイル（CSV / TSV / 改行・空白区切り、# でコメント可）")
		quiet    = flag.Bool("q", false, "個別出力を抑制し、終了ステータスのみで判定")
		which    = flag.Bool("which", false, "一致した最も具体的な CIDR も表示する")
		check    = flag.Bool("check", false, "走査対象 IP の素性を RDAP→WHOIS で照会する（-which 併用時は該当 CIDR も）")
	)
	flag.Usage = func() { printHelp(flag.CommandLine.Output()) }
	flag.Parse()

	// 無指定（フラグも引数も無し）なら help を表示して終了する。
	if flag.NFlag() == 0 && flag.NArg() == 0 {
		printHelp(os.Stdout)
		return
	}

	outColor := useColor(os.Stdout)

	// whois は RDAP 失敗時のフォールバックにのみ使う。無ければ RDAP のみで動く。
	var whoisPath string
	if *check {
		whoisPath, _ = exec.LookPath("whois")
	}

	checker := &cidrcheck.Checker{}

	if *cidrList != "" {
		for _, cidr := range strings.Split(*cidrList, ",") {
			if err := checker.Add(cidr); err != nil {
				fail(err)
			}
		}
	}
	if *cidrFile != "" {
		// CSV / TSV / 改行区切りのいずれでも読み込める。
		if err := checker.LoadFile(*cidrFile); err != nil {
			fail(err)
		}
	}
	if checker.Len() == 0 {
		fmt.Fprintln(os.Stderr, "ipcheck: no CIDR given; use -cidr or -file (run 'ipcheck -h' for help)")
		os.Exit(2)
	}

	allMatched := true
	checkIP := func(ip string) {
		var matched netip.Prefix
		var ok bool
		var err error
		if *which {
			matched, ok, err = checker.MatchString(ip)
		} else {
			ok, err = checker.ContainsString(ip)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			allMatched = false
			return
		}
		if !ok {
			allMatched = false
		}

		if !*quiet {
			switch {
			case ok && *which:
				fmt.Printf("%-39s MATCH %s\n", ip, matched)
			case ok:
				fmt.Printf("%-39s MATCH\n", ip)
			default:
				fmt.Printf("%-39s no-match\n", ip)
			}
		}

		if *check {
			// 走査対象の IP の素性を照会する（対象 CIDR 一覧自体は照会しない）。
			runIdentity(ip, ip, whoisPath, outColor)
			// which モードでは該当 CIDR（最具体・上位 1 件）のネットワークアドレスも照会。
			if ok && *which {
				net := matched.Addr().String()
				runIdentity(fmt.Sprintf("%s (%s)", matched, net), net, whoisPath, outColor)
			}
		}
	}

	if args := flag.Args(); len(args) > 0 {
		for _, ip := range args {
			checkIP(ip)
		}
	} else {
		// 引数がなければ stdin から 1 行 1 IP で読む。
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				checkIP(line)
			}
		}
		if err := sc.Err(); err != nil {
			fail(err)
		}
	}

	if !allMatched {
		os.Exit(1)
	}
}

// runIdentity は target の素性を RDAP→WHOIS で照会し、label 付きで表示する。
// プライベート/予約 IP はレジストリ情報が無いので照会せず明示する。取得失敗は
// 致命的扱いにせず黄色の警告として出す。
func runIdentity(label, target, whoisPath string, color bool) {
	if a, err := netip.ParseAddr(target); err == nil && isNonPublic(a) {
		fmt.Printf("    %-45s (プライベート/予約 IP — レジストリ情報なし)\n", label)
		return
	}
	id, err := lookupIdentity(target, whoisPath)
	if err != nil {
		line := fmt.Sprintf("    %-45s 警告: 素性情報を取得できません: %v", label, err)
		fmt.Println(colorize(line, ansiYellow, color))
		return
	}
	fmt.Printf("    %-45s [%s] %s\n", label, id.Source, id.Summary())
}

// isNonPublic はグローバルに到達不能（プライベート・ループバック・リンクローカル・
// マルチキャスト・未指定）な、レジストリ照会対象外のアドレスかを返す。
func isNonPublic(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified()
}

// colorize は enabled が真のとき s を ANSI コードで囲む。
func colorize(s, code string, enabled bool) string {
	if !enabled {
		return s
	}
	return code + s + ansiReset
}

// useColor は f に対して色付けすべきかを返す。NO_COLOR=無効 / CLICOLOR_FORCE=強制 /
// それ以外は f が端末（TTY）のときのみ色付けする。
func useColor(f *os.File) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if v := os.Getenv("CLICOLOR_FORCE"); v != "" && v != "0" {
		return true
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// printHelp writes the English usage/help text to w. Shown when ipcheck is run
// with no flags and no arguments, and on -h / flag errors.
func printHelp(w io.Writer) {
	fmt.Fprint(w, `ipcheck - check whether IP addresses fall within a set of CIDRs (IPv4/IPv6)

Usage:
  ipcheck [flags] [IP ...]

IPs may be passed as arguments, or read from stdin (one per line) when none are
given. At least one CIDR source (-cidr or -file) is required.

Flags:
  -cidr string   comma-separated CIDRs (e.g. 10.0.0.0/8,192.168.0.0/16)
  -file string   CIDR file: CSV / TSV / newline- or space-separated ('#' starts a comment)
  -which         also print the most specific matching CIDR
  -check         look up each IP's identity (org, ASN, country, netname) via
                 RDAP->WHOIS and RIPEstat. With -which the matched CIDR is also
                 looked up; the CIDR list itself is never looked up.
  -q             quiet: suppress per-IP output, rely on exit status only
  -h             show this help

Exit status:
  0  every checked IP matched at least one CIDR
  1  at least one IP did not match
  2  usage or input error

Examples:
  ipcheck -cidr 10.0.0.0/8,192.168.0.0/16 10.1.2.3 8.8.8.8
  ipcheck -file ranges.csv 10.1.2.3
  printf '10.1.2.3\n8.8.8.8\n' | ipcheck -file ranges.txt
  ipcheck -which -cidr 10.0.0.0/8,10.1.2.0/24 10.1.2.3
  ipcheck -check -cidr 0.0.0.0/0 8.8.8.8
`)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ipcheck:", err)
	os.Exit(2)
}
