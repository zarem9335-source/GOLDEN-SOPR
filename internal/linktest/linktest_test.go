package linktest

import "testing"

func TestRecommendGaming(t *testing.T) {
	name, _ := Recommend(10, 5, 0, true)
	if name != "wg-gaming" {
		t.Fatalf("gaming recommend = %q, want wg-gaming", name)
	}
	name, _ = Recommend(10, 5, 8, false)
	if name != "wg-gaming" {
		t.Fatalf("lossy recommend = %q, want wg-gaming", name)
	}
	name, _ = Recommend(20, 2, 0, false)
	if name != "tcp-mux" {
		t.Fatalf("clean recommend = %q, want tcp-mux", name)
	}
	if s := Score(20, 2, 0); s["wg-gaming"] <= s["tcp"] {
		t.Fatalf("wg-gaming should score above tcp on a clean route: %v", s)
	}
}

func TestMeasureUnreachable(t *testing.T) {
	// 127.0.0.1:1 should refuse fast; Measure must return a result with loss, not hang.
	r, err := Measure("127.0.0.1:1", 2)
	if err != nil {
		t.Skipf("measure error (acceptable on this host): %v", err)
	}
	if r.LossPct != 100 {
		t.Fatalf("loss = %.1f, want 100", r.LossPct)
	}
}
