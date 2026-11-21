package core

import (
	"kitsune/internal/proto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRotateLogs(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "xray.log")
	small := filepath.Join(dir, "sing-box.log")
	_ = os.WriteFile(big, []byte(strings.Repeat("a", 2000)), 0o640)
	_ = os.WriteFile(small, []byte("ok"), 0o640)
	_ = os.WriteFile(big+".1", []byte("старый"), 0o600)
	_ = os.WriteFile(big+".3", []byte("лишний"), 0o600)
	other := filepath.Join(dir, "notes.log.bak")
	_ = os.WriteFile(other, []byte("чужое"), 0o600)

	RotateLogs(dir, 1000, 2, time.Hour)

	if st, _ := os.Stat(big); st.Size() != 0 {
		t.Error("большой журнал не очищен")
	}
	if b, _ := os.ReadFile(big + ".1"); len(b) != 2000 {
		t.Errorf("архив .1 содержит %d байт, ждали 2000", len(b))
	}
	if b, _ := os.ReadFile(big + ".2"); string(b) != "старый" {
		t.Error("прежний архив не сдвинулся в .2")
	}
	if _, err := os.Stat(big + ".3"); err == nil {
		t.Error("лишний архив .3 не удалён")
	}
	if b, _ := os.ReadFile(small); string(b) != "ok" {
		t.Error("маленький журнал тронут")
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("чужой файл удалён")
	}
	// по возрасту
	old := time.Now().Add(-48 * time.Hour)
	_ = os.Chtimes(big+".2", old, old)
	RotateLogs(dir, 1000, 2, time.Hour)
	if _, err := os.Stat(big + ".2"); err == nil {
		t.Error("архив старше срока не удалён")
	}
}

func TestRawPatchCannotRedirectLogsOrOpenAPI(t *testing.T) {
	out := proto.M{"log": proto.M{"loglevel": "warning"}, "api": proto.M{"tag": "api"}}
	patch := `{"log":{"access":"/etc/cron.d/pwn","error":"/etc/x","loglevel":"debug"},"api":{"tag":"evil"},"routing":{"domainStrategy":"AsIs"}}`
	if err := applyRawPatch(out, patch); err != nil {
		t.Fatal(err)
	}
	lg := out["log"].(proto.M)
	if _, ok := lg["access"]; ok {
		t.Error("access пересобран своим JSON")
	}
	if _, ok := lg["error"]; ok {
		t.Error("error пересобран своим JSON")
	}
	if lg["loglevel"] != "debug" {
		t.Error("безопасные поля должны накладываться")
	}
	if out["api"].(proto.M)["tag"] != "api" {
		t.Error("api переопределён")
	}
	if out["routing"] == nil {
		t.Error("обычные разделы должны накладываться")
	}
	if applyRawPatch(out, "{не json") == nil {
		t.Error("неверный JSON принят")
	}
}
