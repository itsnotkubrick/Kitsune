package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runInstallerBBR(t *testing.T, root string, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("нет bash")
	}
	cmd := exec.Command("bash", append([]string{"../../scripts/install.sh"}, args...)...)
	cmd.Env = append(os.Environ(), "KITSUNE_ROOT="+root, "KITSUNE_NO_SYSTEMD=1", "NO_COLOR=1")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestInstallerHelpMentionsBBR(t *testing.T) {
	out, _ := runInstallerBBR(t, t.TempDir(), "--help")
	if !strings.Contains(out, "--bbr") || !strings.Contains(out, "--no-bbr") {
		t.Errorf("справка не упоминает --bbr / --no-bbr:\n%s", out)
	}
}

func TestInstallerFlagBeforeCommand(t *testing.T) {
	out, _ := runInstallerBBR(t, t.TempDir(), "--bbr", "bogus")
	if !strings.Contains(out, "Unknown command") {
		t.Errorf("флаг до команды должен пропускаться, а команда разбираться:\n%s", out)
	}
	if strings.Contains(out, "Unknown option") {
		t.Errorf("--bbr до команды не должен быть неизвестной опцией:\n%s", out)
	}
}

func TestUninstallRemovesLeftoverBBR(t *testing.T) {
	root := t.TempDir()
	conf := filepath.Join(root, "etc", "sysctl.d", "99-kitsune-bbr.conf")
	if err := os.MkdirAll(filepath.Dir(conf), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(conf, []byte("x\n"), 0o644)
	out, err := runInstallerBBR(t, root, "uninstall", "--yes")
	if err != nil {
		t.Fatalf("uninstall: %v\n%s", err, out)
	}
	if _, err := os.Stat(conf); err == nil {
		t.Errorf("остаток настройки BBR не убран:\n%s", out)
	}
}

func TestInstallerBBRAnswers(t *testing.T) {
	script, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Skip("нет scripts/install.sh")
	}
	s := string(script)
	a := strings.Index(s, "lc() {")
	b := strings.Index(s[a:], "\n")
	lc := s[a : a+b]
	c := strings.Index(s, "    case $(lc \"$REPLY\") in\n      \"\"|y")
	e := strings.Index(s[c:], "esac")
	body := s[c : c+e+4]
	decide := "REPLY=$1\n" + strings.Replace(strings.Replace(body, "return 0 ;;", "echo no ;;", 1), "\"\"|y|yes|д|Д|да|Да|ДА|дА) ;;", "\"\"|y|yes|д|Д|да|Да|ДА|дА) echo yes ;;", 1)
	cases := map[string]string{
		"": "yes", "y": "yes", "Y": "yes", "yes": "yes", "Да": "yes", "д": "yes", "ДА": "yes",
		"n": "no", "no": "no", "NO": "no", "Нет": "no", "НЕТ": "no", "Н": "no", "н": "no", "nope": "no", "не надо": "no",
	}
	for in, want := range cases {
		out, err := exec.Command("bash", "-c", lc+"\nnote() { :; }\n"+decide, "bash", in).CombinedOutput()
		if err != nil {
			t.Fatalf("%q: %v\n%s", in, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("ответ %q: %q, ждали %q", in, got, want)
		}
	}
}

func TestInstallerUnknownOptionBeforeCommand(t *testing.T) {
	out, _ := runInstallerBBR(t, t.TempDir(), "--foo", "install")
	if !strings.Contains(out, "Unknown option: --foo") {
		t.Errorf("должна называться неизвестная опция:\n%s", out)
	}
}

func TestUninstallDryRunKeepsLeftoverBBR(t *testing.T) {
	root := t.TempDir()
	conf := filepath.Join(root, "etc", "sysctl.d", "99-kitsune-bbr.conf")
	_ = os.MkdirAll(filepath.Dir(conf), 0o755)
	_ = os.WriteFile(conf, []byte("x\n"), 0o644)
	out, _ := runInstallerBBR(t, root, "uninstall", "--yes", "--dry-run")
	if _, err := os.Stat(conf); err != nil {
		t.Error("--dry-run не должен удалять файл")
	}
	if strings.Contains(out, "removed") {
		t.Errorf("--dry-run не должен писать «removed»:\n%s", out)
	}
}
