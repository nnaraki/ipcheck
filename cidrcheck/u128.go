package cidrcheck

// u128 は 128 ビット符号なし整数（IPv6 アドレス）を上位/下位の uint64 で表す。
// 比較演算子（==）がそのまま使える comparable な値型。
type u128 struct {
	hi, lo uint64
}

var maxU128 = u128{^uint64(0), ^uint64(0)}

func (a u128) and(b u128) u128 { return u128{a.hi & b.hi, a.lo & b.lo} }
func (a u128) or(b u128) u128  { return u128{a.hi | b.hi, a.lo | b.lo} }
func (a u128) not() u128       { return u128{^a.hi, ^a.lo} }

// less は a < b を返す。
func (a u128) less(b u128) bool {
	if a.hi != b.hi {
		return a.hi < b.hi
	}
	return a.lo < b.lo
}

// lessEq は a <= b を返す。
func (a u128) lessEq(b u128) bool { return !b.less(a) }

// inc は a+1 を返す（下位の桁上がりを上位へ伝播）。a が最大値のときはラップする
// が、呼び出し側で maxU128 を事前に弾くこと。
func (a u128) inc() u128 {
	lo := a.lo + 1
	if lo == 0 {
		return u128{a.hi + 1, 0}
	}
	return u128{a.hi, lo}
}

// maskU128 はプレフィックス長 b（0..128）のネットマスクを返す。
func maskU128(b uint) u128 {
	if b <= 64 {
		// b==0 は 64-0=64 シフトで 0 になり、正しく全ビット 0 になる。
		return u128{hi: ^uint64(0) << (64 - b)}
	}
	return u128{hi: ^uint64(0), lo: ^uint64(0) << (128 - b)}
}
