package optimize

import "testing"

func TestMSSClamp(t *testing.T) {
	if MSSClamp(1280) != 1240 {
		t.Fatalf("MSSClamp(1280) = %d, want 1240", MSSClamp(1280))
	}
	if GamingMSSClamp() != 1240 {
		t.Fatalf("GamingMSSClamp = %d, want 1240", GamingMSSClamp())
	}
	if MSSClamp(500) != 576 {
		t.Fatalf("MSSClamp must floor at 576, got %d", MSSClamp(500))
	}
}
