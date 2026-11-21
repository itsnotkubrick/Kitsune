package main

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"

	"kitsune/internal/check"
	"kitsune/internal/db"
	"kitsune/internal/proto"
)

// Проверка стабильности соединения: человек открывает ссылку в своей сети, страница качает с сервера случайный файл 256 КБ одним
// соединением и следит, не остановились ли данные. Идея проверки заимствована из открытого проекта (MIT).

const stabilitySize = 262144

var (
	stabilityOnce sync.Once
	stabilityData []byte
)

func stabilityBlob() []byte {
	stabilityOnce.Do(func() {
		stabilityData = make([]byte, stabilitySize)
		_, _ = rand.Read(stabilityData) // случайные данные не сжимаются и не кэшируются по дороге
	})
	return stabilityData
}

// stabilityToken проверяет ссылку тем же способом, что подписки: неизвестные адреса получают обычный 404 и считаются попытками подбора.
func stabilityToken(c *gin.Context) (string, bool) {
	ip := c.ClientIP()
	if subBlocked(ip) {
		notFound(c)
		return "", false
	}
	tok := c.Param("token")
	if !db.StabilityLinkValid(tok) {
		subFail(ip)
		notFound(c)
		return "", false
	}
	return tok, true
}

func handleStabilityPage(c *gin.Context) {
	if _, ok := stabilityToken(c); !ok {
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("X-Frame-Options", "DENY")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Security-Policy", connectCSP)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(stabilityPageHTML))
}

func handleStabilityBlob(c *gin.Context) {
	if _, ok := stabilityToken(c); !ok {
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Data(http.StatusOK, "application/octet-stream", stabilityBlob())
}

func handleStabilityResult(c *gin.Context) {
	tok, ok := stabilityToken(c)
	if !ok {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2048)
	var in struct {
		Kind  string `json:"kind"`
		Note  string `json:"note"`
		OK    bool   `json:"ok"`
		Bytes int    `json:"bytes"`
		MS    int    `json:"ms"`
	}
	if c.ShouldBindJSON(&in) != nil || in.Bytes > stabilitySize || in.MS > 300000 {
		c.Status(http.StatusBadRequest)
		return
	}
	// «Скачалось» принимаем только если пришёл весь файл: так страницу нельзя заставить соврать про нехватку данных
	if in.OK && in.Bytes < stabilitySize {
		in.OK = false
	}
	if err := db.AddStabilityResult(tok, in.Kind, in.Note, in.OK, in.Bytes, in.MS); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	c.Status(http.StatusNoContent)
}

// ---- Для администратора ----

func handleStabilityNew(c *gin.Context) {
	tok, err := db.NewStabilityLink()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать ссылку"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"url": subBase(c) + "/sub/stability/" + tok})
}

// hasUDPInbound – есть ли в панели включённые UDP-подключения, которые можно поставить в подписке первыми.
func hasUDPInbound() bool {
	inbounds, _ := db.GetInbounds()
	for _, ib := range inbounds {
		if info, ok := proto.Get(proto.Kind(ib.Kind)); ok && ib.Enable && info.Net == "udp" {
			return true
		}
	}
	return false
}

func handleStabilityList(c *gin.Context) {
	total, stalled, last := db.StabilitySummary(14)
	verdict := "none"
	switch {
	case stalled > 0:
		verdict = "stalled"
	case total > 0:
		verdict = "ok"
	}
	c.JSON(http.StatusOK, gin.H{
		"results": db.GetStabilityResults(30), "verdict": verdict, "total": total, "stalled": stalled, "last": last,
		"udp_first": db.GetSetting("sub_udp_first", "0") == "1", "has_udp": hasUDPInbound(),
	})
}

// handleStabilityUDPFirst включает или выключает порядок «UDP-подключения первыми» в подписках.
func handleStabilityUDPFirst(c *gin.Context) {
	var in struct {
		On bool `json:"on"`
	}
	if c.ShouldBindJSON(&in) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные"})
		return
	}
	if err := setUDPFirst(in.On); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "udp_first": in.On})
}

func setUDPFirst(on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	err := db.SetSetting("sub_udp_first", v)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

func init() {
	// кнопка «Исправить» в паспорте безопасности
	check.FixHooks["udpfirst"] = func(string) (string, error) {
		if !hasUDPInbound() {
			return "", errors.New("в панели нет UDP-подключений (Hysteria2, TUIC, AmneziaWG): сначала создайте их")
		}
		if err := setUDPFirst(true); err != nil {
			return "", err
		}
		return "В подписках UDP-подключения теперь идут первыми. Клиенты получат новый порядок при обновлении подписки", nil
	}
}

const stabilityPageHTML = `<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Проверка соединения</title>
<style>
:root{--bg:#1b1b1e;--card:#27272b;--text:#f4f4f6;--mu:#a6a6b0;--ok:#4ade80;--bad:#f87171;--line:rgba(128,128,140,.3);color-scheme:dark}
@media (prefers-color-scheme:light){:root{--bg:#ececef;--card:#fff;--text:#16161a;--mu:#6a6a76;--ok:#1f8a5e;--bad:#c0392b;color-scheme:light}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:20px 16px 48px}
main{max-width:520px;margin:0 auto;display:flex;flex-direction:column;gap:14px}
h1{font-size:22px;margin:6px 0 0}.card{background:var(--card);border-radius:20px;padding:18px}
p{margin:0 0 10px;color:var(--mu)}label{display:block;font-size:14px;color:var(--mu);margin:12px 0 6px}
select,input{width:100%;padding:12px;border-radius:12px;border:1.5px solid var(--line);background:transparent;color:var(--text);font:inherit}
button{margin-top:14px;width:100%;padding:14px;border-radius:99px;border:0;background:var(--text);color:var(--bg);font:inherit;font-weight:700;cursor:pointer}
button:disabled{opacity:.5}.bar{height:8px;border-radius:9px;background:var(--line);overflow:hidden;margin-top:12px}.bar i{display:block;height:100%;width:0;background:var(--text);transition:width .15s linear}select option{background:var(--card);color:var(--text)}
.v{font-size:18px;font-weight:700;margin-top:12px}.ok{color:var(--ok)}.bad{color:var(--bad)}small{color:var(--mu)}
</style></head><body><main>
<h1>Проверка соединения</h1>
<div class="card"><p>Отключите VPN и откройте эту страницу в той сети, которую хотите проверить: мобильный интернет или домашний Wi‑Fi. Страница скачает небольшой файл (256 КБ) с вашего сервера и покажет, не обрывается ли соединение. Ничего не устанавливается.</p>
<label for="k">Где вы сейчас</label><select id="k"><option value="mobile">Мобильный интернет</option><option value="home">Домашний Wi‑Fi или проводной</option><option value="other">Другое</option></select>
<label for="n">Оператор или провайдер (необязательно)</label><input id="n" maxlength="40" placeholder="например, Оператор">
<button id="go" type="button">Проверить</button>
<div class="bar"><i id="b"></i></div><div id="v" class="v"></div><small id="s"></small></div>
</main>
<script>
var TOTAL=262144,STALL=5000,base=location.pathname.replace(/\/$/,"");
function $(i){return document.getElementById(i)}
async function run(){
 $("go").disabled=true;$("v").className="v";$("v").textContent="Проверяю…";$("s").textContent="";$("b").style.width="0";
 var got=0,stalled=false,ctrl=new AbortController(),t0=performance.now(),last=t0;
 var timer=setInterval(function(){if(performance.now()-last>STALL){stalled=true;ctrl.abort()}},500);
 try{var r=await fetch(base+"/blob?"+Date.now(),{cache:"no-store",signal:ctrl.signal});var rd=r.body.getReader();
  for(;;){var x=await rd.read();if(x.done)break;got+=x.value.length;last=performance.now();$("b").style.width=Math.round(got*100/TOTAL)+"%"}}
 catch(e){}
 clearInterval(timer);
 var ms=Math.round(performance.now()-t0),ok=got>=TOTAL;
 var sent=false;
 try{var pr=await fetch(base+"/result",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({kind:$("k").value,note:$("n").value.slice(0,40),ok:ok,bytes:got,ms:ms})});sent=pr.ok}catch(e){}
 var rep="Проверка стабильности соединения: "+(ok?"соединение не обрывается":"данные остановились")+", получено "+Math.round(got/1024)+" КБ из 256 за "+ms+" мс";
 var tail=sent?" Результат отправлен администратору.":" Результат не отправился: пришлите администратору этот текст вручную: "+rep+".";
 $("go").disabled=false;
 if(ok){$("v").className="v ok";$("v").textContent="Соединение не обрывается";$("s").textContent="Файл скачан за "+ms+" мс."+(sent?"":tail)}
 else if(got===0){$("v").className="v bad";$("v").textContent="Данные не пришли";$("s").textContent="Сервер не ответил. Возможно, он недоступен из этой сети."+(sent?"":tail)}
 else{$("v").className="v bad";$("v").textContent="Передача остановилась";$("s").textContent="Пришло "+Math.round(got/1024)+" КБ из 256, затем данные остановились. Так выглядит остановка передачи."+tail}
}
$("go").onclick=run;
</script></body></html>`
