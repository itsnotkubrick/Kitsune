package sub

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestHappRoutingProfileFromServices(t *testing.T) {
	c := ClientRouting{Mode: "services", Services: []string{"youtube", "telegram"}, BlockAds: true, Custom: "DOMAIN-SUFFIX,bank.example,DIRECT\nIP-CIDR,203.0.113.0/24,DIRECT"}
	p := HappRoutingProfile(c, 1790000000)
	if p["GlobalProxy"] != "false" || p["Name"] != "Kitsune" || p["LastUpdated"] != "1790000000" {
		t.Fatalf("%v", p)
	}
	ps := p["ProxySites"].([]string)
	if len(ps) != 2 || ps[0] != "geosite:youtube" {
		t.Fatalf("ProxySites: %v", ps)
	}
	if got := p["ProxyIp"].([]string); len(got) != 1 || got[0] != "geoip:telegram" {
		t.Fatalf("ProxyIp: %v", got)
	}
	if got := p["BlockSites"].([]string); len(got) != 1 || got[0] != "geosite:category-ads-all" {
		t.Fatalf("BlockSites: %v", got)
	}
	ds := p["DirectSites"].([]string)
	di := p["DirectIp"].([]string)
	if len(ds) != 1 || ds[0] != "domain:bank.example" || di[0] != "geoip:private" || di[1] != "203.0.113.0/24" {
		t.Fatalf("Direct: %v %v", ds, di)
	}
}

func TestHappRoutingLinkRoundTrip(t *testing.T) {
	link := HappRoutingLink(ClientRouting{Mode: "local-direct"}, 5)
	if !strings.HasPrefix(link, "happ://routing/onadd/") {
		t.Fatal(link)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "happ://routing/onadd/"))
	var back map[string]any
	if err != nil || json.Unmarshal(raw, &back) != nil || back["GlobalProxy"] != "true" {
		t.Fatalf("%v %v", err, back)
	}
	if HappRoutingLink(ClientRouting{Mode: "all"}, 1) != "" {
		t.Fatal("без раздельной маршрутизации ссылка не нужна")
	}
}

func TestHeadersByClient(t *testing.T) {
	s := DefaultSubSettings()
	s.Announce, s.SupportURL, s.ProviderID, s.ExpireNotice, s.InfoText = "Привет", "https://t.me/support", "abc123", true, "Продлите"
	h := http.Header{}
	s.ApplyHeaders(h, false, ClientRouting{Mode: "services", Services: []string{"youtube"}})
	if h.Get("Profile-Title") == "" || h.Get("Announce") == "" || h.Get("Support-Url") == "" {
		t.Fatalf("общие заголовки: %v", h)
	}
	if h.Get("Providerid") != "" || h.Get("Routing") != "" || h.Get("Sub-Expire") != "" {
		t.Fatalf("не-Happ не получает расширенные заголовки: %v", h)
	}
	h = http.Header{}
	s.ApplyHeaders(h, true, ClientRouting{Mode: "services", Services: []string{"youtube"}})
	if h.Get("Providerid") != "abc123" || h.Get("Sub-Expire") != "1" || h.Get("Sub-Info-Text") != "Продлите" || !strings.HasPrefix(h.Get("Routing"), "happ://routing/onadd/") {
		t.Fatalf("Happ: %v", h)
	}
}

func TestValidateClamps(t *testing.T) {
	s := DefaultSubSettings()
	s.Title = strings.Repeat("я", 40)
	s.UpdateHours = 0
	s.SupportURL = "javascript:alert(1)"
	if msg := s.Validate(); msg == "" {
		t.Fatal("ссылка не с http(s) должна отклоняться")
	}
	s.SupportURL = "https://t.me/x"
	if msg := s.Validate(); msg != "" || len([]rune(s.Title)) != 25 || s.UpdateHours != 12 {
		t.Fatalf("%q %d %d", msg, len([]rune(s.Title)), s.UpdateHours)
	}
}
