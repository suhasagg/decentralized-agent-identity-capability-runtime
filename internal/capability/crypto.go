package capability

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
)

func signingBytes(t Token) ([]byte, error) {
	c := t
	c.Signature = ""
	sort.Strings(c.Scope.Actions)
	return json.Marshal(c)
}

func Sign(t Token, privateKey ed25519.PrivateKey) (Token, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Token{}, errors.New("invalid private key")
	}
	b, err := signingBytes(t)
	if err != nil {
		return Token{}, err
	}
	t.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, b))
	return t, nil
}

func VerifySignature(t Token, publicKey ed25519.PublicKey) error {
	b, err := signingBytes(t)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(t.Signature)
	if err != nil || !ed25519.Verify(publicKey, b, sig) {
		return errors.New("invalid capability signature")
	}
	return nil
}

func RandomNonce() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
