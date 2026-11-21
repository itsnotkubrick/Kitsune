#!/usr/bin/env bash
# Снимает ответы сайта на набор проверочных запросов и печатает их в сравнимом виде: статус, заголовки (без Date, значения ETag и
# Last-Modified заменены на метки, потому что они зависят от файла и соли), хеш тела.
# Запуск: tools/compare-site.sh https://example.com [curl-опции…]   (например, -k для самоподписанного сертификата, --http3)
# Снять эталон с настоящего nginx и ответы Kitsune, затем: diff <(compare-site.sh A) <(compare-site.sh B)
set -u
BASE=${1:?укажите адрес, например https://example.com}; shift
OPTS=("$@")
probe() { # метод путь [заголовок…]
  local m=$1 p=$2; shift 2
  local hdr=() h; for h in "$@"; do hdr+=(-H "$h"); done
  local hf bf; hf=$(mktemp); bf=$(mktemp)
  echo "=== $m $p ${*:+[$*]}"
  local mode=(-X "$m"); [ "$m" = HEAD ] && mode=(-I)
  curl -sS "${mode[@]}" ${hdr[@]+"${hdr[@]}"} ${OPTS[@]+"${OPTS[@]}"} --max-time 15 -D "$hf" -o "$bf" "$BASE$p" 2>&1 || echo "ОШИБКА curl"
  [ "$m" = HEAD ] && : > "$bf" # у HEAD curl -I пишет заголовки в -o, тело пустое
  # заголовки: первая строка статуса, остальные в нижнем регистре и по алфавиту; Date убираем, валидаторы заменяем метками
  tr -d '\r' < "$hf" | sed -E '/^$/d' | awk 'NR==1{sub(/^HTTP\/[0-9.]+ /,"HTTP "); print "1 " $0; next}
    {k=tolower($1); sub(/:.*/,"",k); if(k=="date") next; if(k=="etag"){print "2 etag: <var>";next} if(k=="last-modified"){print "2 last-modified: <var>";next} print "2 " tolower($0)}' | sort -s -k1,1 | cut -d' ' -f2-
  # тело сравнивается побайтно (в том числе CRLF): хеш и размер
  printf 'body-sha256: %s (%s bytes)\n' "$(shasum -a 256 < "$bf" | cut -c1-16)" "$(wc -c < "$bf" | tr -d ' ')"
  rm -f "$hf" "$bf"
}
probe GET /
probe HEAD /
probe GET /index.html
probe GET //
probe GET "/?x=1"
probe GET /favicon.ico
probe GET /robots.txt
probe GET /нет-такого
probe POST /
probe PUT /
probe DELETE /
probe OPTIONS /
probe GET / "Range: bytes=0-9"
probe GET / "If-Modified-Since: Tue, 01 Jan 2030 00:00:00 GMT"
