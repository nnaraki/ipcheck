// Package cidrcheck は CIDR の集合に対する IP アドレスの所属判定を提供する。
// IPv4 / IPv6 の両方に対応し、標準ライブラリの net/netip 上に実装している（外部依存ゼロ）。
//
// 数万件規模の CIDR を高頻度で引く用途を想定し、各 CIDR を整数レンジ [lo, hi]
// に展開してソート・マージし、クエリは二分探索（O(log m)、m はマージ後レンジ数）で
// 行う。フラットな配列に対する探索なのでキャッシュ効率がよく、確定後の読み取りは
// ロックフリーで並行クエリに対して安全。
//
// 使い方の流れ:
//
//	c, _ := cidrcheck.New("10.0.0.0/8", "2001:db8::/32")
//	c.Build()                       // 任意。高頻度クエリ前に一度呼ぶと初回遅延を回避
//	ok, _ := c.ContainsString("10.1.2.3")
//
// CIDR をすべて登録し終えてからクエリを発行する使い方なら、Contains /
// ContainsString は複数 goroutine から同時に呼び出して安全。
package cidrcheck

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
)

// Checker は登録済みの CIDR 集合を保持し、IP がいずれかに含まれるかを判定する。
// ゼロ値のまま利用できる。
type Checker struct {
	mu       sync.Mutex
	prefixes []netip.Prefix       // 登録された生のプレフィックス（インデックスの入力）
	idx      atomic.Pointer[index] // 確定済みの検索インデックス（読み取りはロックフリー）
}

// index は確定済みの検索構造。生成後は不変で、複数 goroutine から同時に読める。
//
// v4/v6 は所属判定（Contains）用にマージ済みのレンジ集合。lpm4/lpm6 は
// 「どの CIDR に当たったか」（Match）用の最長プレフィックス一致インデックスで、
// 元の CIDR の素性を保持するためマージしない。
type index struct {
	v4   []rng32  // ソート済み・重複なし・マージ済み
	v6   []rng128 // 同上
	lpm4 *lpmIndex[uint32]
	lpm6 *lpmIndex[u128]
}

type rng32 struct{ lo, hi uint32 }
type rng128 struct{ lo, hi u128 }

// New は与えられた CIDR 文字列（例: "10.0.0.0/8"）から Checker を生成する。
// パースに失敗した最初の CIDR でエラーを返す。
func New(cidrs ...string) (*Checker, error) {
	c := &Checker{}
	for _, cidr := range cidrs {
		if err := c.Add(cidr); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Add は単一の CIDR プレフィックスをパースして登録する。前後の空白は無視する。
// 空文字列は何もせず無視する。"/" を含まない場合は単一ホスト
// （IPv4 なら /32、IPv6 なら /128）として扱う。登録するとインデックスは無効化され、
// 次回クエリ時（または Build 呼び出し時）に再構築される。
func (c *Checker) Add(cidr string) error {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return nil
	}

	var p netip.Prefix
	if strings.Contains(cidr, "/") {
		parsed, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("cidrcheck: 不正な CIDR %q: %w", cidr, err)
		}
		// Masked() でホストビットをゼロ化し、純粋なプレフィックスにする。
		p = parsed.Masked()
	} else {
		// "/" を含まない場合はホストアドレス（/32 or /128）として扱う。
		addr, err := netip.ParseAddr(cidr)
		if err != nil {
			return fmt.Errorf("cidrcheck: 不正なアドレス %q: %w", cidr, err)
		}
		addr = addr.Unmap()
		p = netip.PrefixFrom(addr, addr.BitLen())
	}

	c.mu.Lock()
	c.prefixes = append(c.prefixes, p)
	c.idx.Store(nil) // 集合が変わったのでインデックスを無効化
	c.mu.Unlock()
	return nil
}

// fieldSep は CIDR の区切り文字（カンマ・タブ・空白などの空白類）を判定する。
// これにより CSV / TSV / 改行区切り / 空白区切りを区別なく扱える。
func fieldSep(r rune) bool { return r == ',' || unicode.IsSpace(r) }

// LoadReader は r から CIDR を読み込んで登録する。各行をカンマ・タブ・空白で
// 区切り、得られた各トークンを CIDR として登録するため、CSV・TSV・改行区切り・
// 空白区切りのいずれの形式でも読み込める。'#' 以降は行内コメントとして無視する。
// トークンが不正な CIDR ならエラーを返す（ラベル列やヘッダ行が混在するファイルは
// そのまま読めないため、その場合は列を抽出してから渡すこと）。
func (c *Checker) LoadReader(r io.Reader) error {
	sc := bufio.NewScanner(r)
	// 全 CIDR が 1 行に並ぶ CSV/TSV にも備えて行バッファを広げる（最大 64MB）。
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i] // 行内コメントを除去
		}
		for _, tok := range strings.FieldsFunc(line, fieldSep) {
			if err := c.Add(tok); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

// LoadFile はファイルを開いて LoadReader で読み込む。CSV / TSV / 改行区切り
// （および空白区切り）に対応する。
func (c *Checker) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return c.LoadReader(f)
}

// Build はここまでに登録した CIDR から検索インデックスを構築する。任意。
// 呼ばなくても初回クエリ時に自動で構築されるが、高頻度クエリの直前に一度呼んで
// おくと、初回クエリのビルド遅延と lazy ビルドの競合を避けられる。
func (c *Checker) Build() { c.ensureIndex() }

func (c *Checker) ensureIndex() *index {
	if idx := c.idx.Load(); idx != nil {
		return idx
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if idx := c.idx.Load(); idx != nil { // ロック取得後に二重チェック
		return idx
	}
	idx := buildIndex(c.prefixes)
	c.idx.Store(idx)
	return idx
}

// Contains は ip が登録済みのいずれかの CIDR に含まれるかを返す。
// IPv4-mapped IPv6（::ffff:a.b.c.d）は IPv4 として正規化してから判定する。
func (c *Checker) Contains(ip netip.Addr) bool {
	idx := c.idx.Load()
	if idx == nil {
		idx = c.ensureIndex()
	}
	ip = ip.Unmap()
	if ip.Is4() {
		return idx.containsV4(beUint32(ip))
	}
	return idx.containsV6(toU128(ip))
}

// ContainsString は ip をパースして Contains を呼ぶ。ip が不正なアドレスの
// 場合はエラーを返す。
func (c *Checker) ContainsString(ip string) (bool, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false, fmt.Errorf("cidrcheck: 不正なアドレス %q: %w", ip, err)
	}
	return c.Contains(addr), nil
}

// Match は ip を含む最も具体的な（プレフィックス長が最大の）CIDR を、登録時の形
// （ホストビットをゼロ化済み）で返す。例えば 10.0.0.0/8 と 10.1.0.0/16 の両方を
// 登録した状態で 10.1.2.3 を引くと 10.1.0.0/16 を返す。一致しなければ ok=false。
// IPv4-mapped IPv6（::ffff:a.b.c.d）は IPv4 として正規化してから判定する。
func (c *Checker) Match(ip netip.Addr) (netip.Prefix, bool) {
	idx := c.idx.Load()
	if idx == nil {
		idx = c.ensureIndex()
	}
	ip = ip.Unmap()
	if ip.Is4() {
		return idx.lpm4.match(beUint32(ip))
	}
	return idx.lpm6.match(toU128(ip))
}

// MatchString は ip をパースして Match を呼ぶ。ip が不正なアドレスの場合は
// エラーを返す。
func (c *Checker) MatchString(ip string) (netip.Prefix, bool, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return netip.Prefix{}, false, fmt.Errorf("cidrcheck: 不正なアドレス %q: %w", ip, err)
	}
	p, ok := c.Match(addr)
	return p, ok, nil
}

// Len は登録済みプレフィックス数を返す（マージ前の生の件数）。
func (c *Checker) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.prefixes)
}

// --- インデックス構築 ---

func buildIndex(prefixes []netip.Prefix) *index {
	var v4 []rng32
	var v6 []rng128
	var l4 []lpmItem[uint32]
	var l6 []lpmItem[u128]
	for _, p := range prefixes {
		if p.Addr().Is4() {
			lo, hi := v4Range(p)
			v4 = append(v4, rng32{lo, hi})
			l4 = append(l4, lpmItem[uint32]{lo, hi, p})
		} else {
			lo, hi := v6Range(p)
			v6 = append(v6, rng128{lo, hi})
			l6 = append(l6, lpmItem[u128]{lo, hi, p})
		}
	}
	return &index{
		v4:   mergeV4(v4),
		v6:   mergeV6(v6),
		lpm4: buildLPM(l4, func(a, b uint32) bool { return a < b }),
		lpm6: buildLPM(l6, u128.less),
	}
}

func beUint32(ip netip.Addr) uint32 {
	a := ip.As4()
	return binary.BigEndian.Uint32(a[:])
}

func toU128(ip netip.Addr) u128 {
	a := ip.As16()
	return u128{
		hi: binary.BigEndian.Uint64(a[0:8]),
		lo: binary.BigEndian.Uint64(a[8:16]),
	}
}

func v4Range(p netip.Prefix) (uint32, uint32) {
	net := beUint32(p.Addr())
	b := uint(p.Bits()) // 0..32
	// b==0 のとき 32-0=32 シフトは Go では 0 になり、mask=0 で正しく全域になる。
	mask := ^uint32(0) << (32 - b)
	return net & mask, net | ^mask
}

func v6Range(p netip.Prefix) (u128, u128) {
	net := toU128(p.Addr())
	mask := maskU128(uint(p.Bits())) // 0..128
	return net.and(mask), net.or(mask.not())
}

func mergeV4(rs []rng32) []rng32 {
	if len(rs) == 0 {
		return nil
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo < rs[j].lo })
	out := rs[:1]
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		merge := r.lo <= last.hi // 重複・包含・接触
		if !merge && last.hi != ^uint32(0) {
			merge = r.lo == last.hi+1 // 隙間なく隣接
		}
		if merge {
			if r.hi > last.hi {
				last.hi = r.hi
			}
		} else {
			out = append(out, r)
		}
	}
	return out
}

func mergeV6(rs []rng128) []rng128 {
	if len(rs) == 0 {
		return nil
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo.less(rs[j].lo) })
	out := rs[:1]
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		merge := !last.hi.less(r.lo) // r.lo <= last.hi
		if !merge && last.hi != maxU128 {
			merge = r.lo == last.hi.inc() // 隙間なく隣接
		}
		if merge {
			if last.hi.less(r.hi) {
				last.hi = r.hi
			}
		} else {
			out = append(out, r)
		}
	}
	return out
}

// --- 検索（二分探索） ---

func (idx *index) containsV4(ip uint32) bool {
	rs := idx.v4
	// lo > ip となる最初の位置の直前が候補レンジ。
	i := sort.Search(len(rs), func(i int) bool { return rs[i].lo > ip }) - 1
	return i >= 0 && ip <= rs[i].hi
}

func (idx *index) containsV6(ip u128) bool {
	rs := idx.v6
	i := sort.Search(len(rs), func(i int) bool { return ip.less(rs[i].lo) }) - 1
	return i >= 0 && ip.lessEq(rs[i].hi)
}
