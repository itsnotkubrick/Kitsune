// Команда release: ключи подписи и выпуск подписанных сборок Kitsune.
//
//	go run ./cmd/release keygen -out ~/.kitsune-release
//	go run ./cmd/release build -version 0.2 -repo owner/Kitsune -key ~/.kitsune-release/private.key -notes "Что нового"
//	go run ./cmd/release verify -manifest dist/latest.json -pub <открытый ключ>
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"kitsune/internal/release"
	"kitsune/internal/update"
)

// extra – дополнительные команды, которые подключают отдельные файлы сборки.
var extra = map[string]func(args []string){}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fatal("команды: keygen, build, verify")
	}
	switch os.Args[1] {
	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		out := fs.String("out", "", "каталог для ключей (создаётся с правами 700)")
		_ = fs.Parse(os.Args[2:])
		if *out == "" {
			fatal("укажите -out")
		}
		if strings.HasPrefix(*out, "~") {
			home, _ := os.UserHomeDir()
			*out = filepath.Join(home, strings.TrimPrefix(*out, "~"))
		}
		if _, err := os.Stat(filepath.Join(*out, "private.key")); err == nil {
			fatal("%s уже существует – не перезаписываю (потеря ключа сделает обновления невозможными)", filepath.Join(*out, "private.key"))
		}
		priv, pub, err := release.GenerateKey()
		if err != nil {
			fatal("%v", err)
		}
		_ = os.MkdirAll(*out, 0o700)
		if err := os.WriteFile(filepath.Join(*out, "private.key"), []byte(priv+"\n"), 0o600); err != nil {
			fatal("%v", err)
		}
		_ = os.WriteFile(filepath.Join(*out, "public.key"), []byte(pub+"\n"), 0o644)
		fmt.Println("Закрытый ключ:", filepath.Join(*out, "private.key"), "(храните в секрете, сделайте копию)")
		fmt.Println("Открытый ключ:", pub)
	case "build":
		fs := flag.NewFlagSet("build", flag.ExitOnError)
		version := fs.String("version", "", "версия, например 0.2")
		repo := fs.String("repo", "", "репозиторий GitHub: владелец/название")
		key := fs.String("key", "", "файл закрытого ключа")
		out := fs.String("out", "dist", "каталог результата")
		notes := fs.String("notes", "", "что нового")
		manifest := fs.String("manifest-url", "", "адрес latest.json (по умолчанию из -repo)")
		_ = fs.Parse(os.Args[2:])
		if *version == "" || *repo == "" || *key == "" {
			fatal("нужны -version, -repo и -key")
		}
		seed, err := os.ReadFile(*key)
		if err != nil {
			fatal("%v", err)
		}
		m, err := release.Build(release.Options{Version: *version, Repo: *repo, SeedB64: string(seed), OutDir: *out, Notes: *notes, ManifestURL: *manifest})
		if err != nil {
			fatal("%v", err)
		}
		fmt.Printf("Готово: %s/latest.json (версия %s, сборок: %d)\n", *out, m.Version, len(m.Assets))
		fmt.Println("Загрузите в релиз GitHub v" + *version + " файлы kitsune-* и latest.json.")
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		manifest := fs.String("manifest", "", "файл или адрес latest.json")
		pub := fs.String("pub", "", "открытый ключ (base64)")
		_ = fs.Parse(os.Args[2:])
		var data []byte
		var err error
		if strings.HasPrefix(*manifest, "http") {
			resp, e := http.Get(*manifest)
			if e != nil {
				fatal("%v", e)
			}
			defer resp.Body.Close()
			var m update.Manifest
			if json.NewDecoder(resp.Body).Decode(&m) != nil {
				fatal("манифест не разобран")
			}
			check(m, *pub)
			return
		}
		if data, err = os.ReadFile(*manifest); err != nil {
			fatal("%v", err)
		}
		var m update.Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			fatal("манифест не разобран: %v", err)
		}
		check(m, *pub)
	default:
		if f, ok := extra[os.Args[1]]; ok {
			f(os.Args[2:])
			return
		}
		fatal("неизвестная команда %q", os.Args[1])
	}
}

func check(m update.Manifest, pub string) {
	bad := 0
	for plat, a := range m.Assets {
		if err := update.VerifyAsset(pub, a); err != nil {
			fmt.Printf("ПРОВАЛ %s: %v\n", plat, err)
			bad++
		} else {
			fmt.Printf("ok     %s %s\n", plat, a.SHA256[:12])
		}
	}
	if bad > 0 {
		os.Exit(1)
	}
}
