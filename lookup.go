package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

// ipIdentity は IP（または CIDR ネットワークアドレス）の素性情報。
type ipIdentity struct {
	Source  string // 登録情報の取得元: "rdap" / "whois"（ASN のみなら "ripestat"）
	Org     string // 登録組織名
	ASN     string // 起源 AS 番号（"AS15169"）
	ASName  string // AS の保有組織名
	Country string // 国コード
	NetName string // ネットワーク名
	Handle  string // ハンドル
	Range   string // 割当レンジ（"start - end" または CIDR）
}

// Summary は非空フィールドを 1 行にまとめる。
func (id *ipIdentity) Summary() string {
	var parts []string
	if id.Org != "" {
		parts = append(parts, "org="+id.Org)
	}
	if id.ASN != "" {
		as := "as=" + id.ASN
		if id.ASName != "" {
			as += " (" + id.ASName + ")"
		}
		parts = append(parts, as)
	}
	if id.Country != "" {
		parts = append(parts, "country="+id.Country)
	}
	if id.NetName != "" {
		parts = append(parts, "net="+id.NetName)
	}
	if id.Range != "" {
		parts = append(parts, "range="+id.Range)
	}
	if id.Handle != "" {
		parts = append(parts, "handle="+id.Handle)
	}
	if len(parts) == 0 {
		return "(情報なし)"
	}
	return strings.Join(parts, "  ")
}

// lookupIdentity は target（IP 文字列）の素性を照会する。登録情報は RDAP→WHOIS で
// 取得し、起源 AS 番号は RIPEstat で補完する。AS の取得に失敗しても登録情報が取れて
// いればそれを返す（その逆も同様）。両方失敗した場合のみエラーを返す。
func lookupIdentity(target, whoisPath string) (*ipIdentity, error) {
	id, regErr := lookupRegistry(target, whoisPath)
	asn, asName, asErr := lookupASN(target)
	if regErr != nil && asErr != nil {
		return nil, fmt.Errorf("%v; asn: %v", regErr, asErr)
	}
	if id == nil { // 登録情報は取れなかったが AS は取れた場合
		id = &ipIdentity{Source: "ripestat"}
	}
	if asErr == nil {
		id.ASN = asn
		id.ASName = asName
	}
	return id, nil
}

// lookupRegistry は登録情報を RDAP で照会し、失敗したら whois にフォールバックする。
// whoisPath が空（whois 未インストール）なら RDAP のみ試みる。
func lookupRegistry(target, whoisPath string) (*ipIdentity, error) {
	rctx, rcancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer rcancel()
	id, rerr := lookupRDAP(rctx, target)
	if rerr == nil {
		return id, nil
	}
	if whoisPath == "" {
		return nil, fmt.Errorf("rdap: %v; whois 未インストール", rerr)
	}
	wctx, wcancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer wcancel()
	id, werr := lookupWhois(wctx, whoisPath, target)
	if werr != nil {
		return nil, fmt.Errorf("rdap: %v; whois: %v", rerr, werr)
	}
	return id, nil
}

// --- RDAP（HTTP） ---

type rdapResponse struct {
	Handle       string       `json:"handle"`
	Name         string       `json:"name"`
	Country      string       `json:"country"`
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	Entities     []rdapEntity `json:"entities"`
}

type rdapEntity struct {
	Handle     string          `json:"handle"`
	Roles      []string        `json:"roles"`
	VcardArray json.RawMessage `json:"vcardArray"`
	Entities   []rdapEntity    `json:"entities"`
}

func lookupRDAP(ctx context.Context, ip string) (*ipIdentity, error) {
	// rdap.org は適切な RIR の RDAP サーバへリダイレクトするブートストラップ。
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://rdap.org/ip/"+ip, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "ipcheck/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return parseRDAP(body)
}

// parseRDAP は RDAP の IP 応答 JSON から素性を抽出する（ネットワーク非依存）。
func parseRDAP(body []byte) (*ipIdentity, error) {
	var r rdapResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	id := &ipIdentity{
		Source:  "rdap",
		Country: r.Country,
		NetName: r.Name,
		Handle:  r.Handle,
		Org:     rdapOrg(r.Entities),
	}
	if r.StartAddress != "" {
		id.Range = r.StartAddress + " - " + r.EndAddress
	}
	return id, nil
}

// rdapOrg は entities から組織名（vCard の fn）を返す。registrant ロールを優先し、
// 無ければ最初に見つかった fn を返す。
func rdapOrg(entities []rdapEntity) string {
	if fn := findFn(entities, true); fn != "" {
		return fn
	}
	return findFn(entities, false)
}

func findFn(entities []rdapEntity, registrantOnly bool) string {
	for _, e := range entities {
		if fn := vcardFn(e.VcardArray); fn != "" {
			if !registrantOnly || hasRole(e.Roles, "registrant") {
				return fn
			}
		}
		if sub := findFn(e.Entities, registrantOnly); sub != "" {
			return sub
		}
	}
	return ""
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}

// vcardFn は jCard 配列 ["vcard", [["fn",{},"text","Org"],...]] から fn の値を返す。
func vcardFn(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if err := json.Unmarshal(arr[1], &props); err != nil {
		return ""
	}
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var name string
		if json.Unmarshal(p[0], &name) != nil || name != "fn" {
			continue
		}
		var val string
		if json.Unmarshal(p[3], &val) == nil {
			return val
		}
	}
	return ""
}

// --- WHOIS（os/exec） ---

func lookupWhois(ctx context.Context, whoisPath, ip string) (*ipIdentity, error) {
	out, err := exec.CommandContext(ctx, whoisPath, ip).Output()
	if err != nil {
		return nil, err
	}
	return parseWhois(out), nil
}

// parseWhois は whois 出力から代表的なフィールドを抽出する（ネットワーク非依存）。
// ARIN（OrgName/NetName/CIDR）と RIPE/APNIC（netname/descr/inetnum）の双方に対応。
func parseWhois(out []byte) *ipIdentity {
	id := &ipIdentity{Source: "whois"}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := splitKV(line)
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "orgname", "org-name", "organization", "owner":
			if id.Org == "" {
				id.Org = v
			}
		case "descr":
			if id.Org == "" { // RIPE 等で組織名の代替として
				id.Org = v
			}
		case "netname":
			if id.NetName == "" {
				id.NetName = v
			}
		case "country":
			if id.Country == "" {
				id.Country = v
			}
		case "cidr", "route", "inetnum", "netrange":
			if id.Range == "" {
				id.Range = v
			}
		}
	}
	return id
}

// --- AS 番号（RIPEstat Data API, HTTP） ---

type ripeStatResp struct {
	Data struct {
		ASNs []struct {
			ASN    int    `json:"asn"`
			Holder string `json:"holder"`
		} `json:"asns"`
		Resource string `json:"resource"`
	} `json:"data"`
}

// lookupASN は RIPEstat（認証不要・RIPE NCC 公式）で ip の起源 AS を引く。
// 複数 AS（MOAS）の場合は先頭（上位 1 件）を返す。
func lookupASN(ip string) (asn, holder string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	u := "https://stat.ripe.net/data/prefix-overview/data.json?resource=" + url.QueryEscape(ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "ipcheck/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", err
	}
	return parseRIPEStatASN(body)
}

// parseRIPEStatASN は RIPEstat prefix-overview の応答から AS 番号と保有組織名を
// 抽出する（ネットワーク非依存）。
func parseRIPEStatASN(body []byte) (asn, holder string, err error) {
	var r ripeStatResp
	if err := json.Unmarshal(body, &r); err != nil {
		return "", "", err
	}
	if len(r.Data.ASNs) == 0 {
		return "", "", fmt.Errorf("ASN なし")
	}
	a := r.Data.ASNs[0]
	return fmt.Sprintf("AS%d", a.ASN), a.Holder, nil
}

func splitKV(line string) (k, v string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return "", "", false
	}
	k = strings.TrimSpace(line[:i])
	v = strings.TrimSpace(line[i+1:])
	if k == "" || v == "" {
		return "", "", false
	}
	return k, v, true
}
