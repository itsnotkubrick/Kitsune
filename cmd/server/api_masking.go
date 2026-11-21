package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"kitsune/internal/db"
	"kitsune/internal/masking"
	"kitsune/internal/proto"
	"kitsune/internal/selfsteal"
	"kitsune/internal/stub"
)

func realityInbounds() []db.Inbound {
	var out []db.Inbound
	inbounds, _ := db.GetInbounds()
	for _, ib := range inbounds {
		if ib.Kind == string(proto.VlessReality) || ib.Kind == string(proto.VlessXHTTP) {
			out = append(out, ib)
		}
	}
	return out
}

func handleMaskingGet(c *gin.Context) {
	type rv struct {
		ID   int    `json:"id"`
		Tag  string `json:"tag"`
		Kind string `json:"kind"`
		SNI  string `json:"sni"`
	}
	list := []rv{}
	for _, ib := range realityInbounds() {
		list = append(list, rv{ib.ID, ib.Tag, ib.Kind, proto.ParseSettings(ib.Settings).SNI})
	}
	cur := db.GetSetting("stub_site", "nginx")
	c.JSON(http.StatusOK, gin.H{
		"stubs": stub.ListWith(cur), "stub": cur, "has_custom": stub.Custom() != "",
		"reality": list, "defaults": proto.DefaultSNIs,
	})
}

// stubReadRetry – пауза между повторами чтения настройки заглушки при ошибке базы (в тестах обнуляется).
var stubReadRetry = 500 * time.Millisecond

// readSettingRetry читает настройку и повторяет попытку при ошибке базы (занятость, ввод-вывод). found=false без ошибки –
// настройки в базе нет.
func readSettingRetry(key string) (v string, found bool, err error) {
	for i := 0; i < 3; i++ {
		if v, found, err = db.LookupSetting(key); err == nil {
			return v, found, nil
		}
		time.Sleep(stubReadRetry)
	}
	return "", false, err
}

func writeSetting(key, v string) {
	if err := db.SetSetting(key, v); err != nil {
		log.Printf("Не удалось сохранить настройку %s: %v", key, err)
	}
}

// initStub готовит заглушки при старте: данные установки (initStubSeed), своя страница и выбор страницы для первой
// настройки. Вызывается до запуска ядер и сайта на домене, а также после восстановления из копии.
func initStub() {
	initStubSeed()
	custom, _, err := readSettingRetry("stub_custom_html")
	if err != nil {
		log.Printf("Не удалось прочитать свою страницу-заглушку, выбор не меняю: %v", err)
		return
	}
	stub.SetCustom(custom) // своя страница-заглушка, если пользователь её загрузил
	cur, _, err := readSettingRetry("stub_site")
	if err != nil {
		log.Printf("Не удалось прочитать выбранную заглушку, выбор не меняю: %v", err)
		return
	}
	if !stub.Exists(cur) { // первая настройка или мусор в значении: у каждого сервера своя случайная заглушка
		writeSetting("stub_site", stub.Pick(cur))
	}
}

func handleStubSet(c *gin.Context) {
	var req struct {
		ID string `json:"id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || !stub.Exists(req.ID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неизвестная заглушка"})
		return
	}
	if err := stubSetWith(req.ID, applyCores); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Заглушка применена"})
}

// stubSetWith сохраняет выбранную заглушку, обновляет сайт на домене и ядра; если применение упало, возвращает прежнюю.
func stubSetWith(id string, apply func() error) error {
	prev := db.GetSetting("stub_site", "")
	_ = db.SetSetting("stub_site", id)
	selfsteal.Apply()
	if err := apply(); err != nil {
		_ = db.SetSetting("stub_site", prev)
		selfsteal.Apply()
		return err
	}
	return nil
}

// handleStubRandom выбирает новую случайную заглушку (своя страница пользователя при этом остаётся сохранённой).
func handleStubRandom(c *gin.Context) {
	id, err := stubRandomWith(applyCores)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Выбрана новая случайная заглушка", "id": id})
}

// stubRandomWith сохраняет новую случайную заглушку и применяет её; если применение упало, возвращает прежнее значение.
func stubRandomWith(apply func() error) (string, error) {
	prev := db.GetSetting("stub_site", "")
	id := stub.RandomID(prev)
	_ = db.SetSetting("stub_site", id)
	selfsteal.Apply()
	if err := apply(); err != nil {
		_ = db.SetSetting("stub_site", prev)
		selfsteal.Apply()
		return "", err
	}
	return id, nil
}

// handleStubPage отдаёт HTML заглушки для предпросмотра (пусто – текущая).
func handleStubPage(c *gin.Context) {
	id := c.Query("id")
	if id == "" {
		id = db.GetSetting("stub_site", "nginx")
	}
	if !stub.Exists(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неизвестная заглушка"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"html": stub.HTML(id)})
}

// serverIPv4 – публичный IPv4 сервера для поиска соседних сайтов.
func serverIPv4(c *gin.Context) string {
	host := linkHost(c)
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil && !ip.IsLoopback() && !ip.IsPrivate() {
			return ip.String()
		}
		return ""
	}
	addrs, _ := net.LookupHost(host)
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsPrivate() {
			return ip.String()
		}
	}
	return ""
}

func handleMaskingScan(c *gin.Context) {
	// Поиск обращается к соседним адресам хостера: запускаем только после явного подтверждения в интерфейсе.
	var req struct {
		Confirm bool `json:"confirm"`
	}
	_ = c.ShouldBindJSON(&req)
	if !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Поиск среди соседей по подсети нужно подтвердить: он отправляет короткие TLS-запросы на соседние адреса вашего хостера"})
		return
	}
	ip := serverIPv4(c)
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Не удалось определить публичный IPv4 сервера. Укажите адрес сервера в «Настройках»."})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()
	cands := masking.Scan(ctx, ip, 12)
	c.JSON(http.StatusOK, gin.H{"server_ip": ip, "candidates": cands})
}

// handleMaskingSNI меняет сайт маскировки у всех REALITY-подключений (аналог kit sni).
func handleMaskingSNI(c *gin.Context) {
	var req struct {
		SNI       string `json:"sni"`
		Random    bool   `json:"random"`
		InboundID int    `json:"inbound_id"` // 0 – все REALITY-подключения (XHTTP со своим сайтом не трогаем)
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	sni := strings.ToLower(strings.TrimSpace(req.SNI))
	if req.Random || sni == "" {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(proto.DefaultSNIs))))
		sni = proto.DefaultSNIs[n.Int64()]
	}
	if net.ParseIP(sni) != nil || !strings.Contains(sni, ".") || strings.ContainsAny(sni, " /:") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Укажите доменное имя сайта, например www.example.com"})
		return
	}
	// Свой домен (он смотрит на этот же сервер) нельзя поставить как обычный чужой сайт: REALITY пошёл бы за «сайтом» к самому себе
	// и замкнулся бы на собственный порт 443. Для своего домена нужен сайт-заглушка (kit selfsteal), его адрес и становится target.
	target, tErr := maskingTarget(sni, selfsteal.Domain(), resolvesToThisServer(c, sni))
	if tErr != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": tErr})
		return
	}
	// Проверка: сайт должен отвечать по TLS 1.3 и HTTP/2
	warn := ""
	if target == selfsteal.Addr { // свою заглушку проверять снаружи нечем: она отвечает только при выпущенном сертификате
		warn = ""
	} else if addrs, err := net.LookupHost(sni); err == nil && len(addrs) > 0 {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
		if _, ok := masking.Check(ctx, addrs[0], sni); !ok {
			warn = "Сайт не ответил по TLS 1.3 и HTTP/2 – маскировка может работать плохо."
		}
		cancel()
	} else {
		warn = "Не удалось проверить сайт (нет DNS-ответа)."
	}
	if warn != "" && c.Query("force") != "1" {
		c.JSON(http.StatusConflict, gin.H{"error": warn, "needs_force": true})
		return
	}
	n := 0
	for _, ib := range realityInbounds() {
		if req.InboundID != 0 && ib.ID != req.InboundID {
			continue
		}
		if req.InboundID == 0 && ib.Kind != string(proto.VlessReality) {
			continue
		}
		s := proto.ParseSettings(ib.Settings)
		old := s.SNI
		s.SNI, s.Target = sni, target
		s.WithOldSNI(old, time.Now().Add(7*24*time.Hour).Unix())
		if _, err := db.DB.Exec("UPDATE inbounds SET sni = ?, settings = ? WHERE id = ?", sni, s.JSON(), ib.ID); err == nil {
			n++
		}
	}
	if err := applyCores(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Сайт маскировки изменён у подключений: " + strconvI(n) + ". Клиенты получат новые ссылки при обновлении подписки.", "sni": sni})
}

// handleStubCustomGet отдаёт текст своей страницы-заглушки для редактирования.
func handleStubCustomGet(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"html": stub.Custom(), "max": stub.MaxCustom})
}

// handleStubCustomSet сохраняет свою страницу-заглушку и сразу делает её активной.
func handleStubCustomSet(c *gin.Context) {
	var req struct {
		HTML string `json:"html"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	h := strings.TrimSpace(req.HTML)
	switch {
	case h == "":
		c.JSON(http.StatusBadRequest, gin.H{"error": "Страница пустая"})
		return
	case len(h) > stub.MaxCustom:
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Страница больше %d КБ: уберите лишнее или вынесите картинки в уменьшенный вид", stub.MaxCustom>>10)})
		return
	case !strings.Contains(strings.ToLower(h), "<"):
		c.JSON(http.StatusBadRequest, gin.H{"error": "Это не похоже на HTML-страницу"})
		return
	}
	if err := db.SetSetting("stub_custom_html", h); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	stub.SetCustom(h)
	_ = db.SetSetting("stub_site", stub.CustomID)
	selfsteal.Apply() // сайт на своём домене перечитывает страницу
	if err := applyCores(); err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "Своя страница сохранена, но ядро не приняло конфиг: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Своя страница сохранена и применена"})
}

// handleStubCustomDelete удаляет свою страницу и возвращает стандартную заглушку.
func handleStubCustomDelete(c *gin.Context) {
	_ = db.SetSetting("stub_custom_html", "")
	stub.SetCustom("")
	if db.GetSetting("stub_site", "") == stub.CustomID {
		_ = db.SetSetting("stub_site", stub.RandomID(""))
	}
	selfsteal.Apply()
	if err := applyCores(); err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "Своя страница удалена, но ядро не приняло конфиг: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Своя страница удалена, выбрана случайная заглушка"})
}

// maskingTarget выбирает target REALITY для нового сайта маскировки. Пустой target значит «сам сайт на порту 443».
// own – домен смотрит на этот сервер, selfDomain – домен, на который уже включена своя страница-заглушка.
func maskingTarget(sni, selfDomain string, own bool) (target, errText string) {
	if selfDomain != "" && strings.EqualFold(sni, selfDomain) {
		return selfsteal.Addr, ""
	}
	if own {
		return "", "Домен " + sni + " смотрит на этот же сервер: как чужой сайт его ставить нельзя, REALITY замкнётся на сам себя, и сайт перестанет открываться. Включите сайт на своём домене: в этом же разделе, в поле «Сайт на своём домене», или командой kit selfsteal " + sni + " на сервере. Панель выпустит сертификат и поднимет заглушку."
	}
	return "", ""
}

// resolvesToThisServer: имя указывает на адрес самого сервера (его интерфейсов или публичный адрес из запроса).
func resolvesToThisServer(c *gin.Context, host string) bool {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return false
	}
	mine := map[string]bool{serverIPv4(c): true}
	if ifs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range ifs {
			if ipn, ok := a.(*net.IPNet); ok {
				mine[ipn.IP.String()] = true
			}
		}
	}
	for _, a := range addrs {
		if mine[a] {
			return true
		}
	}
	return false
}

// handleSelfStealGet – состояние сайта на своём домене.
func handleSelfStealGet(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"domain": selfsteal.Domain()})
}

// handleSelfStealSet включает сайт-заглушку на своём домене: сертификат Let's Encrypt, локальная страница и target REALITY на неё.
// То же, что делает команда kit selfsteal, но из панели: службе не нужно останавливаться, порт 80 для проверки домена держит она сама.
func handleSelfStealSet(c *gin.Context) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных"})
		return
	}
	domain := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(req.Domain), ".")))
	if !domainRe.MatchString(domain) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Укажите доменное имя латиницей без https://, например vpn.example.com"})
		return
	}
	if len(selfstealInbounds()) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Нет подключений REALITY или XHTTP: сайту на своём домене нечего подменять. Сначала создайте подключение."})
		return
	}
	if ips, err := net.LookupHost(domain); err != nil || len(ips) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "У домена " + domain + " нет A-записи. Создайте её на адрес этого сервера и подождите несколько минут."})
		return
	}
	if !resolvesToThisServer(c, domain) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Домен " + domain + " указывает не на этот сервер. Исправьте A-запись (если домен за прокси вроде Cloudflare, выключите проксирование)."})
		return
	}
	cur := selfsteal.Domain()
	_ = selfsteal.Set(domain)
	if _, _, err := selfsteal.Ensure(domain); err != nil {
		_ = selfsteal.Set(cur)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Let's Encrypt не выдал сертификат: " + err.Error() + ". Частые причины: A-запись ещё не обновилась, порт 80 закрыт файрволом хостера или домен за прокси."})
		return
	}
	n := 0
	for _, ib := range selfstealInbounds() {
		st := proto.ParseSettings(ib.Settings)
		old := st.SNI
		st.SNI, st.Target = domain, selfsteal.Addr
		st.WithOldSNI(old, time.Now().Add(7*24*time.Hour).Unix()) // прежнее имя ещё неделю принимается: клиенты успеют обновить подписку
		if _, err := db.DB.Exec("UPDATE inbounds SET sni = ?, settings = ? WHERE id = ?", domain, st.JSON(), ib.ID); err == nil {
			n++
		}
	}
	selfsteal.Apply()
	if err := applyCores(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Сертификат выпущен, но применить настройки не удалось: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Сайт на домене " + domain + " готов, подключений переключено: " + strconvI(n) + ". Клиенты получат новое имя при обновлении подписки.", "domain": domain})
}

// handleSelfStealOff выключает сайт на своём домене и ставит REALITY обычный чужой сайт: оставить свой домен без заглушки нельзя (замкнётся на себя).
func handleSelfStealOff(c *gin.Context) {
	if selfsteal.Domain() == "" {
		c.JSON(http.StatusOK, gin.H{"message": "Сайт на своём домене и так выключен"})
		return
	}
	_ = selfsteal.Set("")
	n := 0
	for _, ib := range selfstealInbounds() {
		st := proto.ParseSettings(ib.Settings)
		if st.Target != selfsteal.Addr {
			continue
		}
		pick, _ := rand.Int(rand.Reader, big.NewInt(int64(len(proto.DefaultSNIs))))
		st.WithOldSNI(st.SNI, time.Now().Add(7*24*time.Hour).Unix())
		st.SNI, st.Target = proto.DefaultSNIs[pick.Int64()], ""
		if _, err := db.DB.Exec("UPDATE inbounds SET sni = ?, settings = ? WHERE id = ?", st.SNI, st.JSON(), ib.ID); err == nil {
			n++
		}
	}
	selfsteal.Apply()
	if err := applyCores(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Сайт на своём домене выключен, REALITY переключён на обычный сайт из списка (подключений: " + strconvI(n) + "). Выбрать другой можно выше."})
}
