package backup

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/scrypt"
)

// Защищённая копия: заголовок, затем кусками по 64 КБ AES-256-GCM. Ключ выводится из пароля через scrypt.
// Каждый кусок связан со своим номером (nonce), последний помечен отдельным признаком: обрезанный или переставленный файл не откроется.
const (
	encMagic   = "KITSUNEENC1\n"
	encChunk   = 64 << 10
	saltLen    = 16
	prefixLen  = 8
	scryptN    = 1 << 15
	MinPassLen = 8
)

var ErrWrongPassword = errors.New("неверный пароль или файл повреждён")

// IsEncrypted: начало файла похоже на защищённую копию.
func IsEncrypted(head []byte) bool {
	return len(head) >= len(encMagic) && string(head[:len(encMagic)]) == encMagic
}

func deriveAEAD(password string, salt []byte) (cipher.AEAD, error) {
	key, err := scrypt.Key([]byte(password), salt, scryptN, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func chunkNonce(prefix []byte, n uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[prefixLen:], n)
	return nonce
}

type encWriter struct {
	w      io.Writer
	aead   cipher.AEAD
	prefix []byte
	buf    []byte
	n      uint32
}

// NewEncryptWriter шифрует всё, что в него записано. Close обязателен: он дописывает последний кусок.
func NewEncryptWriter(w io.Writer, password string) (io.WriteCloser, error) {
	salt := make([]byte, saltLen)
	prefix := make([]byte, prefixLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(prefix); err != nil {
		return nil, err
	}
	aead, err := deriveAEAD(password, salt)
	if err != nil {
		return nil, err
	}
	hdr := append(append([]byte(encMagic), salt...), prefix...)
	if _, err := w.Write(hdr); err != nil {
		return nil, err
	}
	return &encWriter{w: w, aead: aead, prefix: prefix}, nil
}

func (e *encWriter) seal(final bool) error {
	ad := []byte{0}
	if final {
		ad[0] = 1
	}
	out := e.aead.Seal(nil, chunkNonce(e.prefix, e.n), e.buf, ad)
	e.n++
	e.buf = e.buf[:0]
	_, err := e.w.Write(out)
	return err
}

func (e *encWriter) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		if len(e.buf) == encChunk { // кусок полон и за ним есть данные: он точно не последний
			if err := e.seal(false); err != nil {
				return 0, err
			}
		}
		n := min(encChunk-len(e.buf), len(p))
		e.buf = append(e.buf, p[:n]...)
		p = p[n:]
	}
	return total, nil
}

func (e *encWriter) Close() error { return e.seal(true) }

type decReader struct {
	r      *bufio.Reader
	aead   cipher.AEAD
	prefix []byte
	n      uint32
	out    []byte
	done   bool
}

// NewDecryptReader читает защищённую копию. Неверный пароль определяется по первому куску.
func NewDecryptReader(r io.Reader, password string) (io.Reader, error) {
	br := bufio.NewReader(r)
	hdr := make([]byte, len(encMagic)+saltLen+prefixLen)
	if _, err := io.ReadFull(br, hdr); err != nil || !IsEncrypted(hdr) {
		return nil, errors.New("это не защищённая копия Kitsune")
	}
	aead, err := deriveAEAD(password, hdr[len(encMagic):len(encMagic)+saltLen])
	if err != nil {
		return nil, err
	}
	d := &decReader{r: br, aead: aead, prefix: hdr[len(encMagic)+saltLen:]}
	if err := d.next(); err != nil { // сразу проверяем пароль
		return nil, err
	}
	return d, nil
}

func (d *decReader) next() error {
	buf := make([]byte, encChunk+d.aead.Overhead())
	n, err := io.ReadFull(d.r, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return err
	}
	buf = buf[:n]
	_, peekErr := d.r.Peek(1)
	final := peekErr != nil
	ad := []byte{0}
	if final {
		ad[0] = 1
	}
	plain, err := d.aead.Open(nil, chunkNonce(d.prefix, d.n), buf, ad)
	if err != nil {
		return ErrWrongPassword
	}
	d.n++
	d.out, d.done = plain, final
	return nil
}

func (d *decReader) Read(p []byte) (int, error) {
	for len(d.out) == 0 {
		if d.done {
			return 0, io.EOF
		}
		if err := d.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, d.out)
	d.out = d.out[n:]
	return n, nil
}
