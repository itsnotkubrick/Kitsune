package importer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// MaxConfigSize – предел размера config.json Xray.
const MaxConfigSize = 8 << 20

// ReadXrayConfig читает подключения из config.json Xray (в нём хранит подключения Marzban). Файл только читается.
// Если у подключений есть списки clients (обычный Xray), из них собираются и пользователи; у Marzban они пустые:
// пользователи лежат в его базе.
func ReadXrayConfig(path string) (*Data, error) {
	st, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, errors.New("нет доступа к файлу настроек Xray")
		}
		return nil, errors.New("файл настроек Xray не найден")
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("файл настроек Xray не найден")
	}
	if st.Size() > MaxConfigSize {
		return nil, fmt.Errorf("файл настроек Xray больше %d МБ", MaxConfigSize>>20)
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, errors.New("нет доступа к файлу настроек Xray")
		}
		return nil, errors.New("не удалось прочитать файл настроек Xray")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxConfigSize+1))
	if err != nil || len(raw) > MaxConfigSize {
		return nil, errors.New("не удалось прочитать файл настроек Xray")
	}
	return parseXrayConfig(raw)
}

func parseXrayConfig(raw []byte) (*Data, error) {
	var cfg struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	raw = stripJSONC(raw)
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("файл настроек Xray пустой")
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) {
			return nil, errors.New("файл настроек Xray неверной формы: ожидается объект с полем inbounds – списком подключений")
		}
		return nil, errors.New("файл настроек Xray не разобран: это не JSON или файл повреждён")
	}
	if len(cfg.Inbounds) == 0 {
		return nil, errors.New("в файле настроек Xray нет подключений (inbounds)")
	}
	if len(cfg.Inbounds) > MaxInbounds {
		return nil, fmt.Errorf("подключений больше %d", MaxInbounds)
	}
	data := &Data{Source: SourceXray}
	var clients []xuiClient
	for _, ib := range cfg.Inbounds {
		tag := cleanText(toStr(ib["tag"]), 60)
		row := map[string]any{
			"remark": tag, "tag": tag, "enable": true,
			"listen": toStr(ib["listen"]), "port": ib["port"],
			"protocol": strings.ToLower(toStr(ib["protocol"])),
		}
		for in, out := range map[string]string{"settings": "settings", "streamSettings": "stream_settings"} {
			if v, ok := ib[in]; ok {
				b, _ := json.Marshal(v)
				row[out] = string(b)
			}
		}
		in, cl := mapXUIInbound(row)
		data.Inbounds = append(data.Inbounds, in)
		clients = append(clients, cl...)
	}
	data.Users = groupXUIClients(clients, map[string]int64{}, &data.Notes)
	if len(data.Users) > MaxUsers {
		return nil, fmt.Errorf("пользователей больше %d", MaxUsers)
	}
	data.Notes = append(data.Notes, "Из файла настроек Xray переносятся только подключения (и клиенты из их списков clients, если они есть); использованный трафик в нём не хранится.")
	return data, nil
}

// WithConfig заменяет в данных Marzban список подключений (в базе только теги) подключениями из config.json Xray.
func (d *Data) WithConfig(cfg *Data) {
	d.Inbounds = cfg.Inbounds
	d.Notes = append(d.Notes, "Подключения прочитаны из настроек Xray. Сертификаты переносятся путями: проверьте, что файлы есть на этом сервере. Пользователи получат доступ ко всем подключениям Kitsune.")
}

// stripJSONC убирает из настроек Xray то, что допускают Xray и Marzban, но не допускает encoding/json:
// BOM в начале, комментарии // и /* */ и запятые перед закрывающей скобкой. Текст в кавычках не затрагивается.
func stripJSONC(in []byte) []byte {
	in = bytes.TrimPrefix(in, []byte("\xef\xbb\xbf"))
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch {
		case c == '"':
			j := i + 1
			for j < len(in) && in[j] != '"' {
				if in[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(in) {
				j = len(in) - 1
			}
			out = append(out, in[i:j+1]...)
			i = j
		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			end := bytes.Index(in[i+2:], []byte("*/"))
			if end < 0 {
				return in // комментарий не закрыт: пусть разбор сообщит об ошибке
			}
			i += end + 3
			out = append(out, ' ')
		case c == '}' || c == ']':
			k := len(out) - 1
			for k >= 0 && (out[k] == ' ' || out[k] == '\t' || out[k] == '\n' || out[k] == '\r') {
				k--
			}
			if k >= 0 && out[k] == ',' {
				out = append(out[:k], out[k+1:]...)
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}
