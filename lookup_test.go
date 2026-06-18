package main

import "testing"

// ARIN 風の RDAP IP 応答（jCard の fn から組織名を抽出できることを確認）。
const sampleRDAP = `{
  "handle": "8.8.8.0 - 8.8.8.255",
  "startAddress": "8.8.8.0",
  "endAddress": "8.8.8.255",
  "name": "GOGL",
  "country": "US",
  "type": "ALLOCATION",
  "entities": [
    {
      "handle": "ADMIN",
      "roles": ["administrative"],
      "vcardArray": ["vcard", [
        ["version", {}, "text", "4.0"],
        ["fn", {}, "text", "Admin Contact"]
      ]]
    },
    {
      "handle": "GOGL",
      "roles": ["registrant"],
      "vcardArray": ["vcard", [
        ["version", {}, "text", "4.0"],
        ["fn", {}, "text", "Google LLC"],
        ["kind", {}, "text", "org"]
      ]]
    }
  ]
}`

func TestParseRDAP(t *testing.T) {
	id, err := parseRDAP([]byte(sampleRDAP))
	if err != nil {
		t.Fatalf("parseRDAP: %v", err)
	}
	// registrant を優先するので Admin Contact ではなく Google LLC。
	if id.Org != "Google LLC" {
		t.Errorf("Org = %q, want %q", id.Org, "Google LLC")
	}
	if id.Country != "US" {
		t.Errorf("Country = %q, want US", id.Country)
	}
	if id.NetName != "GOGL" {
		t.Errorf("NetName = %q, want GOGL", id.NetName)
	}
	if id.Range != "8.8.8.0 - 8.8.8.255" {
		t.Errorf("Range = %q", id.Range)
	}
	if id.Source != "rdap" {
		t.Errorf("Source = %q, want rdap", id.Source)
	}
}

func TestParseWhoisARIN(t *testing.T) {
	const out = `#
# ARIN WHOIS data
#
NetRange:       8.8.8.0 - 8.8.8.255
CIDR:           8.8.8.0/24
NetName:        GOGL
OrgName:        Google LLC
Country:        US
`
	id := parseWhois([]byte(out))
	if id.Org != "Google LLC" {
		t.Errorf("Org = %q, want Google LLC", id.Org)
	}
	if id.Country != "US" {
		t.Errorf("Country = %q, want US", id.Country)
	}
	if id.NetName != "GOGL" {
		t.Errorf("NetName = %q, want GOGL", id.NetName)
	}
	// CIDR が NetRange より先に拾われる（先勝ち）。
	if id.Range != "8.8.8.0 - 8.8.8.255" {
		t.Errorf("Range = %q, want NetRange 値", id.Range)
	}
}

func TestParseWhoisRIPE(t *testing.T) {
	const out = `% RIPE WHOIS
inetnum:        203.0.113.0 - 203.0.113.255
netname:        EXAMPLE-NET
descr:          Example Organization
country:        NL
`
	id := parseWhois([]byte(out))
	// RIPE は OrgName が無いので descr を組織名の代替に。
	if id.Org != "Example Organization" {
		t.Errorf("Org = %q, want Example Organization", id.Org)
	}
	if id.NetName != "EXAMPLE-NET" {
		t.Errorf("NetName = %q, want EXAMPLE-NET", id.NetName)
	}
	if id.Country != "NL" {
		t.Errorf("Country = %q, want NL", id.Country)
	}
	if id.Range != "203.0.113.0 - 203.0.113.255" {
		t.Errorf("Range = %q", id.Range)
	}
}

func TestParseRIPEStatASN(t *testing.T) {
	const body = `{"data":{"resource":"8.8.8.0/24","asns":[{"asn":15169,"holder":"GOOGLE, US"},{"asn":99999,"holder":"OTHER"}]}}`
	asn, holder, err := parseRIPEStatASN([]byte(body))
	if err != nil {
		t.Fatalf("parseRIPEStatASN: %v", err)
	}
	if asn != "AS15169" { // 上位 1 件
		t.Errorf("asn = %q, want AS15169", asn)
	}
	if holder != "GOOGLE, US" {
		t.Errorf("holder = %q, want GOOGLE, US", holder)
	}
}

func TestParseRIPEStatASNEmpty(t *testing.T) {
	if _, _, err := parseRIPEStatASN([]byte(`{"data":{"asns":[]}}`)); err == nil {
		t.Error("ASN なしの応答ではエラーになるはず")
	}
}

func TestSummaryASN(t *testing.T) {
	id := &ipIdentity{Source: "rdap", Org: "Google LLC", ASN: "AS15169", ASName: "GOOGLE, US"}
	want := "org=Google LLC  as=AS15169 (GOOGLE, US)"
	if got := id.Summary(); got != want {
		t.Errorf("Summary() = %q, want %q", got, want)
	}
}

func TestSummaryEmpty(t *testing.T) {
	id := &ipIdentity{Source: "rdap"}
	if got := id.Summary(); got != "(情報なし)" {
		t.Errorf("Summary() = %q, want (情報なし)", got)
	}
}
