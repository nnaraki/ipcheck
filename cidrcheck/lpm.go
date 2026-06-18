package cidrcheck

import (
	"net/netip"
	"sort"
)

// lpmItem は LPM インデックス構築用の 1 エントリ。
type lpmItem[T any] struct {
	lo, hi T
	pfx    netip.Prefix
}

// lpmIndex は「点を含む最も具体的な CIDR（最長プレフィックス一致）」を返す検索
// インデックス。区間を lo 昇順・同 lo なら hi 降順に並べた平坦配列と、各区間の
// 最近接の包含区間（parent）を持つ。
//
// CIDR 同士は「互いに素」か「一方が他方を完全に包含する」かのどちらか（laminar）
// という性質を利用する。点 p を含む CIDR 群は包含関係で全順序の鎖になるため、
//   1. lo <= p を満たす最後の区間 k を二分探索で求め、
//   2. k が p を含まなければ親をたどる（必ず祖先側に答えがある）
// で最具体の一致が得られる。親たどりの回数は入れ子の深さ（実データでは数段）に収まる。
type lpmIndex[T any] struct {
	lo, hi []T
	pfx    []netip.Prefix
	parent []int32
	less   func(a, b T) bool
}

func buildLPM[T any](items []lpmItem[T], less func(a, b T) bool) *lpmIndex[T] {
	// lo 昇順、同 lo なら hi 降順（包含する側を先に並べる）。
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if less(a.lo, b.lo) {
			return true
		}
		if less(b.lo, a.lo) {
			return false
		}
		return less(b.hi, a.hi)
	})

	n := len(items)
	idx := &lpmIndex[T]{
		lo:     make([]T, n),
		hi:     make([]T, n),
		pfx:    make([]netip.Prefix, n),
		parent: make([]int32, n),
		less:   less,
	}
	stack := make([]int32, 0, 16) // 開いている祖先区間（外側が底、内側が上）
	for i := range items {
		idx.lo[i] = items[i].lo
		idx.hi[i] = items[i].hi
		idx.pfx[i] = items[i].pfx
		// スタック頂上が現区間を包含できなくなる（top.hi < cur.hi）間は pop。
		// 残った頂上は top.lo <= cur.lo かつ top.hi >= cur.hi で、laminar 性質より
		// 現区間を真に包含する最近接の祖先になる。
		for len(stack) > 0 && less(idx.hi[stack[len(stack)-1]], items[i].hi) {
			stack = stack[:len(stack)-1]
		}
		if len(stack) > 0 {
			idx.parent[i] = stack[len(stack)-1]
		} else {
			idx.parent[i] = -1
		}
		stack = append(stack, int32(i))
	}
	return idx
}

// match は ip を含む最も具体的な CIDR を返す。見つからなければ ok=false。
func (l *lpmIndex[T]) match(ip T) (netip.Prefix, bool) {
	// lo <= ip を満たす最後の区間 k を二分探索で求める。
	k := sort.Search(len(l.lo), func(i int) bool { return l.less(ip, l.lo[i]) }) - 1
	for k >= 0 {
		if !l.less(l.hi[k], ip) { // hi[k] >= ip → ip を包含
			return l.pfx[k], true
		}
		k = int(l.parent[k]) // 含まなければ祖先へさかのぼる
	}
	return netip.Prefix{}, false
}
