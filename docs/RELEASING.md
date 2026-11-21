# Публикация Kitsune

Установщик и панель используют стабильный GitHub Release, который GitHub помечает как Latest. Версия задаётся тегом вида `v1.0.0`. При проверке обновлений панель сравнивает этот тег с версией установленного бинарника.

Соберите обе архитектуры из коммита нового тега. Укажите в переменной `signing_key` путь к приватному ключу издателя, соответствующему `RELEASE_PUBKEY` в `scripts/install.sh`.

```bash
set -e
version=1.0.0
signing_key=/path/to/release-signing-key
out=$(mktemp -d)

for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -mod=readonly -trimpath \
    -ldflags "-s -w -X kitsune/internal/version.Version=$version" \
    -o "$out/kitsune-linux-$arch" ./cmd/server
done

cp scripts/install.sh "$out/install.sh"
(
  cd "$out"
  shasum -a 256 install.sh kitsune-linux-amd64 kitsune-linux-arm64 > SHA256SUMS
  ssh-keygen -Y sign -f "$signing_key" -n kitsune-release SHA256SUMS
  awk -F'"' '/^RELEASE_PUBKEY=/{print "kitsune-release " $2}' install.sh > allowed_signers
  ssh-keygen -Y verify -f allowed_signers -I kitsune-release -n kitsune-release \
    -s SHA256SUMS.sig < SHA256SUMS
  shasum -a 256 -c SHA256SUMS
  rm allowed_signers
)
printf 'Файлы релиза: %s\n' "$out"
```

Загрузите пять файлов в черновик GitHub Release и проверьте список вложений. Затем опубликуйте его как стабильный Latest. Архивы исходников, которые GitHub добавляет автоматически, не заменяют бинарники.

Пока репозиторий приватный, первый установщик скачивается из GitHub вручную под авторизованным аккаунтом. Для автоматического скачивания с сервера используйте токен с правами Contents: Read на Kitsune в файле `/etc/kitsune/github-token` с правами `0600`. Установщик из прежней версии, который обращается к ветке `release`, нужно один раз заменить запуском нового подписанного комплекта на сервере.

Для собственного зеркала явно задайте `KITSUNE_BASE_URL`. Панель проверит файл `VERSION` на зеркале, а установщик потребует тот же подписанный комплект файлов.
