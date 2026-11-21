package db

import (
	"database/sql"
	"regexp"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

func TestMTProtoSaltCreatedOnceAndStable(t *testing.T) {
	var err error
	DB, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	DB.SetMaxOpenConns(1)
	if _, err = DB.Exec(`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	initMTProtoSalt()
	first := MTProtoSalt()
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(first) {
		t.Fatalf("соль должна быть 32 байта в hex, получили %q", first)
	}
	initMTProtoSalt() // повторный запуск (перезапуск или обновление) соль не меняет
	if MTProtoSalt() != first {
		t.Fatal("соль изменилась при повторной инициализации")
	}
	if v, _, _ := LookupSetting("mtproto_salt"); v != first {
		t.Fatal("соль не сохранена в базе")
	}
}

func openSaltFileDB(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/salt.db"
	var err error
	DB, err = sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE clients (id INTEGER PRIMARY KEY, name TEXT)`,
	} {
		if _, err = DB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { DB.Close() })
	return path
}

// Соль не сохранилась (база только для чтения): соль пустая, секреты не выдаются.
func TestMTProtoSaltEmptyWhenNotWritable(t *testing.T) {
	openSaltFileDB(t)
	DB.SetMaxOpenConns(1)
	if _, err := DB.Exec(`PRAGMA query_only = ON`); err != nil {
		t.Fatal(err)
	}
	initMTProtoSalt()
	if MTProtoSalt() != "" {
		t.Fatalf("соль должна быть пустой, получили %q", MTProtoSalt())
	}
}

// Одновременная инициализация (панель, cli, второй запуск): у всех одна и та же соль.
func TestMTProtoSaltConcurrentInit(t *testing.T) {
	openSaltFileDB(t)
	DB.SetMaxOpenConns(16)
	const n = 16
	res := make([]string, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			v, _, err := ensureMTProtoSalt() // без общего замка процесса, как в разных процессах
			if err != nil {
				t.Error(err)
			}
			res[i] = v
		}()
	}
	close(start)
	wg.Wait()
	for _, v := range res {
		if !validSalt(v) || v != res[0] {
			t.Fatalf("соли разошлись: %q и %q", res[0], v)
		}
	}
}

// Повреждённая соль заменяется один раз и устойчиво.
func TestMTProtoSaltCorruptReplaced(t *testing.T) {
	openSaltFileDB(t)
	_, _ = DB.Exec(`INSERT INTO settings VALUES ('mtproto_salt', 'abc')`)
	_, _ = DB.Exec(`INSERT INTO clients (name) VALUES ('alice')`)
	initMTProtoSalt()
	first := MTProtoSalt()
	if !validSalt(first) {
		t.Fatalf("соль не заменена: %q", first)
	}
	initMTProtoSalt()
	if MTProtoSalt() != first {
		t.Fatal("соль изменилась при повторной инициализации")
	}
}
