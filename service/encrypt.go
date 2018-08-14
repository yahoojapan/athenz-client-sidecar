package service

import (
	"crypto/des"
	"fmt"
	"strings"
)

type Crypter interface {
	Encrypter
	Decrypter
}

type Decrypter interface {
	Decrypt([]byte) (map[string]string, error)
}

type Encrypter interface {
	Encrypt(map[string]string) ([]byte, error)
}

type crypt struct {
	decrypt
	encrypt
}

type decrypt struct {
	key []byte
}

type encrypt struct {
	key []byte
}

const (
	kvSep  = "="
	valSep = "&"
)

func NewEncrypter() Encrypter {
	// TODO keyに鍵を入れる、Secretをfileにマウントするのがいいかも？
	return &encrypt{}
}

func (e *encrypt) Encrypt(val map[string]string) ([]byte, error) {
	var str string
	for k, v := range val {
		str += fmt.Sprintf("%s%s%s%s", k, kvSep, v, valSep)
	}

	c, err := des.NewTripleDESCipher(e.key)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, des.BlockSize)
	c.Encrypt(encrypted, []byte(str[:len(str)-1]))
	return encrypted, nil
}

func NewDecrypter() Decrypter {
	// TODO keyに鍵を入れる、Secretをfileにマウントするのがいいかも？
	return &decrypt{}
}

func (d *decrypt) Decrypt(encrypted []byte) (map[string]string, error) {
	c, err := des.NewTripleDESCipher(d.key)
	if err != nil {
		return nil, err
	}
	decrypted := make([]byte, des.BlockSize)
	c.Decrypt(decrypted, encrypted)

	m := make(map[string]string)
	for _, val := range strings.Split(string(decrypted), valSep) {
		kv := strings.SplitN(val, kvSep, 2)
		m[kv[0]] = kv[1]
	}

	return m, nil
}
