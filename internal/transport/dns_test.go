package transport

import (
	"strings"
	"testing"
)

func TestDNSFrameRoundTrip(t *testing.T) {
	f := dnsFrame(42, []byte("hello-dns"))
	seq, payload, err := dnsUnframe(f)
	if err != nil || seq != 42 || string(payload) != "hello-dns" {
		t.Fatalf("frame round-trip failed: seq=%d payload=%q err=%v", seq, payload, err)
	}
}

func TestDNSNameRoundTrip(t *testing.T) {
	suffix := dnsSuffix("tok-1", "")
	f := dnsFrame(7, []byte("some game data 1234567890"))
	name := dnsFrameToName(f, suffix)
	if !strings.HasSuffix(name, "."+suffix) {
		t.Fatalf("frame name missing suffix: %s", name)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 {
			t.Fatalf("label too long (%d): %s", len(label), label)
		}
	}
	back, err := dnsNameToFrame(name, suffix)
	if err != nil {
		t.Fatalf("name->frame: %v", err)
	}
	seq, payload, err := dnsUnframe(back)
	if err != nil || seq != 7 || string(payload) != "some game data 1234567890" {
		t.Fatalf("name round-trip failed: seq=%d payload=%q err=%v", seq, payload, err)
	}
}

func TestDNSQueryResponse(t *testing.T) {
	q := dnsBuildQuery(0x1234, "abc.sopr.tunnel")
	id, name, qtype, question, err := dnsParseQuery(q)
	if err != nil || id != 0x1234 || name != "abc.sopr.tunnel" || qtype != 16 {
		t.Fatalf("query parse failed: id=%x name=%q type=%d err=%v", id, name, qtype, err)
	}
	resp := dnsBuildTXTResponse(id, question, "aGVsbG8")
	txt, err := dnsParseTXTResponse(resp)
	if err != nil || txt != "aGVsbG8" {
		t.Fatalf("TXT response failed: txt=%q err=%v", txt, err)
	}
	// Empty TXT answer.
	resp2 := dnsBuildTXTResponse(id, question, "")
	txt2, err := dnsParseTXTResponse(resp2)
	if err != nil || txt2 != "" {
		t.Fatalf("empty TXT failed: txt=%q err=%v", txt2, err)
	}
}

func TestDNSSuffixDiffers(t *testing.T) {
	a := dnsSuffix("token-one", "")
	b := dnsSuffix("token-two", "")
	if a == b {
		t.Fatalf("suffix must depend on the token: %s", a)
	}
	if dnsSuffix("token-one", "") != a {
		t.Fatalf("suffix must be deterministic")
	}
}
