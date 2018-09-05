package cookie

import (
	"sync"
)

type TCookie interface {
	Set(keyID, keyData string)
	Get(keyID string) (string, bool)
	AddVerifier(key string, ver Verifier)
	VerifyAll(f func(string, Verifier) bool)
}

type tCookie struct {
	dataMap   sync.Map // KeyID : KeyData
	verifiers sync.Map
}

const (
	tcookie = "T"
)

func NewTCookie(tcookie, keyID, keyData string) TCookie {
	t := new(tCookie)
	t.dataMap.Store(keyID, keyData)
	return nil
}

func (t *tCookie) Set(keyID, keyData string) {
	t.dataMap.Store(keyID, keyData)
}

func (t *tCookie) Get(keyID string) (string, bool) {
	k, ok := t.dataMap.Load(keyID)
	if !ok {
		return "", false
	}
	return k.(string), true
}

func (t *tCookie) AddVerifier(key string, ver Verifier) {
	t.verifiers.Store(key, ver)
}

func (t *tCookie) VerifyAll(f func(string, Verifier) bool) {
	t.verifiers.Range(func(k, v interface{}) bool {
		f(k.(string), v.(Verifier))
		return true
	})
}
