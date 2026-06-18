package cidrcheck

import (
	"math/rand"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

func TestContains(t *testing.T) {
	c, err := New(
		"10.0.0.0/8",
		"192.168.0.0/16",
		"2001:db8::/32",
		"203.0.113.66", // "/" なしのホスト指定
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"10.255.255.255", true},
		{"11.0.0.1", false},
		{"192.168.50.1", true},
		{"192.169.0.1", false},
		{"2001:db8::1", true},
		{"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"2001:db9::1", false},
		{"203.0.113.66", true},
		{"203.0.113.67", false},
		{"::ffff:10.1.2.3", true}, // IPv4-mapped IPv6 でも IPv4 として一致
	}
	for _, tc := range cases {
		got, err := c.ContainsString(tc.ip)
		if err != nil {
			t.Errorf("ContainsString(%q): %v", tc.ip, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestAddErrors(t *testing.T) {
	c := &Checker{}
	for _, bad := range []string{"not-an-ip", "10.0.0.0/99", "999.0.0.0/8"} {
		if err := c.Add(bad); err == nil {
			t.Errorf("Add(%q): エラーを期待したが nil だった", bad)
		}
	}
}

func TestLoadReader(t *testing.T) {
	const data = `
# 内部レンジ
10.0.0.0/8

172.16.0.0/12
`
	c := &Checker{}
	if err := c.LoadReader(strings.NewReader(data)); err != nil {
		t.Fatalf("LoadReader: %v", err)
	}
	if c.Len() != 2 {
		t.Fatalf("Len = %d, want 2", c.Len())
	}
	if got, _ := c.ContainsString("172.16.5.5"); !got {
		t.Error("172.16.5.5 は 172.16.0.0/12 に一致するはず")
	}
}

// TestLoadFormats は CSV / TSV / 改行区切り / 空白区切り、行内コメントを検証する。
func TestLoadFormats(t *testing.T) {
	cases := map[string]string{
		"改行区切り":      "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n",
		"CSV（1行）":    "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
		"CSV（空白入り）":  "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16",
		"TSV":        "10.0.0.0/8\t172.16.0.0/12\t192.168.0.0/16",
		"行内コメント":     "10.0.0.0/8  # private A\n172.16.0.0/12,192.168.0.0/16 # B,C\n",
		"CSV+改行の混在":  "10.0.0.0/8,172.16.0.0/12\n192.168.0.0/16\n",
		"空白区切り":      "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16",
	}
	for name, data := range cases {
		c := &Checker{}
		if err := c.LoadReader(strings.NewReader(data)); err != nil {
			t.Errorf("[%s] LoadReader: %v", name, err)
			continue
		}
		if c.Len() != 3 {
			t.Errorf("[%s] Len = %d, want 3", name, c.Len())
			continue
		}
		for _, ip := range []string{"10.1.1.1", "172.16.0.1", "192.168.1.1"} {
			if got, _ := c.ContainsString(ip); !got {
				t.Errorf("[%s] %s が一致しない", name, ip)
			}
		}
	}
}

// TestLoadInvalidToken は不正なトークン（ラベル列など）でエラーになることを確認する。
func TestLoadInvalidToken(t *testing.T) {
	c := &Checker{}
	// ラベル付き CSV はそのままでは読めない（厳格に弾く）。
	if err := c.LoadReader(strings.NewReader("10.0.0.0/8,US,private")); err == nil {
		t.Error("不正トークンを含む CSV はエラーになるはず")
	}
}

// TestBoundaries は境界（先頭/末尾アドレス、全域、最大プレフィックス長）を検証する。
func TestBoundaries(t *testing.T) {
	c, _ := New(
		"10.0.0.0/8",
		"0.0.0.0/0", // 全 IPv4
		"::/0",      // 全 IPv6
		"255.255.255.255/32",
		"2001:db8::/128",
	)
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.0", true},        // ネットワークアドレス
		{"10.255.255.255", true},  // ブロードキャスト相当（末尾）
		{"0.0.0.0", true},         // 全域の先頭
		{"255.255.255.255", true}, // 全域の末尾 / /32
		{"::", true},              // 全 IPv6 先頭
		{"2001:db8::", true},
		{"2001:db8::1", true}, // ::/0 に含まれる
	}
	for _, tc := range cases {
		if got, _ := c.ContainsString(tc.ip); got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// TestMergeAdjacent は隣接 CIDR がマージされ、マージ結果が連続レンジとして
// 正しく扱われることを確認する。
func TestMergeAdjacent(t *testing.T) {
	c, _ := New("10.0.0.0/9", "10.128.0.0/9") // 結合すると 10.0.0.0/8 と等価
	idx := c.ensureIndex()
	if len(idx.v4) != 1 {
		t.Fatalf("隣接2件がマージされず len(v4)=%d, want 1", len(idx.v4))
	}
	for _, ip := range []string{"10.0.0.1", "10.127.255.255", "10.128.0.0", "10.255.255.255"} {
		if got, _ := c.ContainsString(ip); !got {
			t.Errorf("%s は結合レンジに含まれるはず", ip)
		}
	}
	if got, _ := c.ContainsString("11.0.0.0"); got {
		t.Error("11.0.0.0 は含まれないはず")
	}
}

// TestConcurrentReads は確定後の Contains が複数 goroutine から安全に呼べることを
// 確認する（-race と併用で意味を持つ）。
func TestConcurrentReads(t *testing.T) {
	c, _ := New("10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32")
	c.Build()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10000; i++ {
				_ = c.Contains(netip.AddrFrom4([4]byte{10, byte(i), byte(i >> 8), 1}))
			}
		}()
	}
	wg.Wait()
}

func TestContainsV6Range(t *testing.T) {
	c, _ := New("2001:db8:abcd::/48")
	in := []string{"2001:db8:abcd::", "2001:db8:abcd:ffff:ffff:ffff:ffff:ffff"}
	out := []string{"2001:db8:abce::", "2001:db8:abcc:ffff:ffff:ffff:ffff:ffff"}
	for _, ip := range in {
		if got, _ := c.ContainsString(ip); !got {
			t.Errorf("%s は /48 に含まれるはず", ip)
		}
	}
	for _, ip := range out {
		if got, _ := c.ContainsString(ip); got {
			t.Errorf("%s は /48 に含まれないはず", ip)
		}
	}
}

// largeChecker は n 件の /24 を持つ Checker を決定的に生成する。
func largeChecker(n int) *Checker {
	c := &Checker{}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < n; i++ {
		a := byte(rng.Intn(223) + 1) // 1..223（マルチキャスト等を避ける）
		b := byte(rng.Intn(256))
		d := byte(rng.Intn(256))
		c.prefixes = append(c.prefixes, netip.PrefixFrom(
			netip.AddrFrom4([4]byte{a, b, d, 0}), 24).Masked())
	}
	c.Build()
	return c
}

// TestMatch は入れ子になった CIDR で最も具体的な一致（LPM）が返ることを検証する。
func TestMatch(t *testing.T) {
	c, _ := New(
		"10.0.0.0/8",
		"10.1.0.0/16",
		"10.1.2.0/24",
		"192.168.0.0/16",
		"2001:db8::/32",
		"2001:db8:abcd::/48",
	)
	cases := []struct {
		ip   string
		want string // 期待する最具体 CIDR。"" は不一致
	}{
		{"10.1.2.3", "10.1.2.0/24"},
		{"10.1.5.5", "10.1.0.0/16"},
		{"10.9.9.9", "10.0.0.0/8"},
		{"192.168.1.1", "192.168.0.0/16"},
		{"8.8.8.8", ""},
		{"2001:db8:abcd::1", "2001:db8:abcd::/48"},
		{"2001:db8:1::1", "2001:db8::/32"},
		{"2001:dead::1", ""},
	}
	for _, tc := range cases {
		p, ok, err := c.MatchString(tc.ip)
		if err != nil {
			t.Errorf("MatchString(%q): %v", tc.ip, err)
			continue
		}
		if tc.want == "" {
			if ok {
				t.Errorf("Match(%q): 不一致を期待したが %s に一致", tc.ip, p)
			}
			continue
		}
		if !ok {
			t.Errorf("Match(%q): %s に一致するはずが不一致", tc.ip, tc.want)
			continue
		}
		if p.String() != tc.want {
			t.Errorf("Match(%q) = %s, want %s", tc.ip, p, tc.want)
		}
	}
}

func BenchmarkContainsSmall(b *testing.B) {
	c, _ := New("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "2001:db8::/32")
	c.Build()
	ip := netip.MustParseAddr("192.168.50.1")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Contains(ip)
	}
}

func BenchmarkContainsLarge(b *testing.B) {
	c := largeChecker(50000)
	ip := netip.MustParseAddr("203.0.113.5")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Contains(ip)
	}
}

func BenchmarkMatchLarge(b *testing.B) {
	c := largeChecker(50000)
	ip := netip.MustParseAddr("203.0.113.5")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.Match(ip)
	}
}
