# ipcheck

CIDR の集合に対して IP アドレスの所属を判定する Go 製ツール。
IPv4 / IPv6 両対応。標準ライブラリ `net/netip` のみで完結（外部依存ゼロ）。

## 構成

- `cidrcheck/` — 判定ロジックのライブラリパッケージ
- `main.go` / `lookup.go` — CLI（`-check` の RDAP/WHOIS/RIPEstat 照会含む）

## インストール（`ipcheck` コマンドとして使う）

どこからでも `ipcheck` で実行できるようにするには、どちらか:

```sh
# 方法 A: go install（~/go/bin へ）
go install .          # → $(go env GOPATH)/bin/ipcheck（既定 ~/go/bin/ipcheck）

# ~/go/bin が PATH に無ければ通す（zsh）。一度だけ:
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc

# 方法 B: /usr/local/bin へ（多くの環境で既に PATH 済み）
make install          # 権限が要る場合は sudo make install
# もしくは手動: go build -o ipcheck . && sudo mv ipcheck /usr/local/bin/
```

確認:

```sh
which ipcheck
ipcheck -cidr 10.0.0.0/8 10.1.2.3
```

> 他メンバーが `go install <path>@latest` でリモート取得できるようにするには、
> モジュールパスを実リポジトリ URL（例 `github.com/nnaraki/ipcheck`）に変更して
> 公開する必要がある。現状の `module ipcheck` はローカル専用。

## CLI

引数なしで実行（または `-h`）すると英語のヘルプを表示する。

```sh
# ビルド（カレントに ./ipcheck を生成。インストール不要で試す場合）
go build -o ipcheck .

# 無指定で実行 → ヘルプ表示
./ipcheck

# CIDR を直接指定して判定
./ipcheck -cidr 10.0.0.0/8,192.168.0.0/16 10.1.2.3 8.8.8.8

# ファイルから読み込み（CSV / TSV / 改行・空白区切りを自動で扱う、# でコメント可）
./ipcheck -file cidrs.txt 10.1.2.3
./ipcheck -file ranges.csv 10.1.2.3   # 10.0.0.0/8,172.16.0.0/12,...
./ipcheck -file ranges.tsv 10.1.2.3   # タブ区切り

# stdin から IP を流し込む
printf '10.1.2.3\n8.8.8.8\n' | ./ipcheck -file cidrs.txt

# 出力を抑制し終了ステータスのみで使う（CI 等）
./ipcheck -q -cidr 10.0.0.0/8 10.1.2.3 && echo "内部IP"

# -which: どの CIDR に当たったか（最も具体的な CIDR）も表示
./ipcheck -which -cidr 10.0.0.0/8,10.1.0.0/16,10.1.2.0/24 10.1.2.3 10.1.9.9
#   10.1.2.3   MATCH 10.1.2.0/24
#   10.1.9.9   MATCH 10.1.0.0/16

# -check: 走査対象 IP の素性（所有組織・AS 番号など）を照会
./ipcheck -check -cidr 0.0.0.0/0 8.8.8.8 1.1.1.1
#   8.8.8.8   MATCH
#       8.8.8.8   [rdap] org=Google LLC  as=AS15169 (GOOGLE - Google LLC)  net=GOGL  range=8.8.8.0 - 8.8.8.255
#   1.1.1.1   MATCH
#       1.1.1.1   [rdap] org=APNIC Research and Development  as=AS13335 (CLOUDFLARENET - Cloudflare, Inc.)  country=AU  net=APNIC-LABS

# -check -which: 該当 CIDR（最具体・上位 1 件）のネットワークアドレスも照会
./ipcheck -check -which -cidr 8.8.8.0/24 8.8.8.8
#   8.8.8.8        MATCH 8.8.8.0/24
#       8.8.8.8                  [rdap] org=Google LLC  net=GOGL  ...
#       8.8.8.0/24 (8.8.8.0)     [rdap] org=Google LLC  net=GOGL  ...
```

終了ステータス: 全 IP 一致=0 / 1 つでも不一致=1 / エラー=2。

### -check（素性 / WHOIS 照会）

`-check` を付けると、走査対象の各 IP の**素性（登録組織名・AS 番号・国・ネットワーク
名・割当レンジ）**を照会して表示する。DNS レコードではなくレジストリ情報を引く。

- **登録情報**: **RDAP（HTTP）を第一に試み、失敗したら `whois` コマンド（`os/exec`）
  にフォールバック**する（`rdap.org` のブートストラップ経由で適切な RIR に解決）。
- **AS 番号**: **RIPEstat Data API**（`stat.ripe.net`、認証不要・RIPE NCC 公式）で
  起源 AS と AS 保有組織名を取得する。複数 AS（MOAS）の場合は上位 1 件。
  登録 org と起源 AS は別物で、両方出すと実態が分かりやすい（例: `1.1.1.1` は
  登録が APNIC Labs だが起源 AS は Cloudflare の AS13335）。
- 登録情報と AS 番号は独立に照会し、**一方が失敗しても取れた方は表示**する。

- 読み込んだ **CIDR 一覧そのものは照会しない**（大量になり得るため）。
- `-which` 併用時のみ、**該当した最も具体的な CIDR（上位 1 件）のネットワーク
  アドレス**を追加で照会する。
- **プライベート/予約 IP**（RFC1918・ループバック等）はレジストリ情報が無いので
  照会せず、その旨を表示する。
- **RDAP・WHOIS とも取得できない場合は黄色の警告**を出し、CIDR 判定は続行する
  （終了ステータスは CIDR 判定の結果のまま）。`whois` 未インストールでも RDAP が
  効けば動作する。
- 色は端末（TTY）出力時のみ自動で付く。`NO_COLOR` で無効化、`CLICOLOR_FORCE` で
  強制（パイプ・リダイレクト時は既定でプレーン）。

## 入力ファイル形式

`-file`（および `LoadFile` / `LoadReader`）は次を区別なく読み込む:

- 改行区切り（1 行 1 CIDR）
- CSV（カンマ区切り、1 行に複数可）
- TSV（タブ区切り）
- 空白区切り

各行をカンマ・タブ・空白で区切り、得られた各トークンを CIDR として登録する。
`#` 以降は行内コメントとして無視。IPv4 / IPv6 / `/` なしのホスト指定が混在してよい。

> **注意:** すべてのトークンを CIDR として厳格にパースする（タイポを握りつぶさない）。
> ラベル列やヘッダ行を含む多列の CSV/TSV（例: `10.0.0.0/8,US,private`）はそのままでは
> エラーになる。その場合は対象列のみを抽出してから渡すこと。列指定での読み込みが
> 必要なら対応可能。

## ライブラリとして使う

```go
import "ipcheck/cidrcheck"

c, _ := cidrcheck.New("10.0.0.0/8", "2001:db8::/32")

// ファイルからまとめて読み込み（CSV / TSV / 改行・空白区切りに対応、# コメント可）
c.LoadFile("ranges.csv")
// io.Reader からでも可: c.LoadReader(r)

c.Build()                              // 任意。高頻度クエリ前に呼ぶと初回遅延を回避
ok, _ := c.ContainsString("10.1.2.3")  // true

// netip.Addr を直接渡す版（パース済みで毎回呼ぶホットパス向け）
addr := netip.MustParseAddr("10.1.2.3")
c.Contains(addr)

// どの CIDR に当たったか（最も具体的な = 最長プレフィックス一致）を返す
p, ok, _ := c.MatchString("10.1.2.3") // p="10.1.2.0/24", ok=true
p, ok = c.Match(addr)
```

CIDR をすべて登録し終えてからクエリを発行する使い方なら、`Contains` /
`ContainsString` は複数 goroutine から同時に呼び出して安全（確定後の読み取りは
ロックフリー）。

## 性能・アルゴリズム

数万件規模を高頻度で引けるよう、線形走査ではなく **レンジ + 二分探索** で実装:

1. 各 CIDR を整数レンジ `[lo, hi]` に展開（IPv4=`uint32`、IPv6=自前 `u128`）
2. ソートして重複・隣接レンジをマージ（`10.0.0.0/9` + `10.128.0.0/9` → 1 レンジ）
3. クエリはマージ後配列への二分探索 `O(log m)`（m = マージ後レンジ数）

フラット配列への探索なのでキャッシュ効率がよく、ポインタ追跡の多い trie より
実測で速いことが多い。インデックスは初回クエリ時に遅延構築され、確定後は
`atomic.Pointer` 経由のロックフリー読み取り。`Add` すると無効化され次回再構築される。

### Match（どの CIDR に当たったか）

`Match` / `MatchString` は所属判定に加えて「一致した最も具体的な CIDR」を返す。
CIDR は互いに素か包含関係のどちらか（laminar）という性質を使い、`lo` 昇順に
並べた配列への二分探索 + 各区間の親ポインタをたどることで、最長プレフィックス
一致を `O(log n + 入れ子深さ)` で求める（マージ済みレンジとは別に、元の CIDR の
素性を保持する索引を持つ）。

実測（Apple M2 Pro, `go test -bench`）:

| 操作 | CIDR 件数 | 1 クエリあたり | alloc |
|---|---|---|---|
| `Contains` | 4 件 | ~4.5 ns | 0 |
| `Contains` | 50,000 件 | ~13 ns | 0 |
| `Match` | 50,000 件 | ~33 ns | 0 |

件数が 1 万倍になっても二分探索なのでコストはほぼ一定。`Match` は元 CIDR を保持
する索引を別に引くぶん `Contains` よりやや重いが、それでも数十 ns・アロケーション
なし。さらに高度な用途（全一致 CIDR の列挙など）が必要になったら、LPM トライ
（例: `github.com/gaissmai/bart`）へ差し替える余地もある。

## テスト / ベンチ

```sh
go test ./...
go test -bench=. -benchmem ./cidrcheck/
```
