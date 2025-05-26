package goSecureChat

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"log"
)

func generateRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	return privKey, &privKey.PublicKey
}

func generateSessionKey() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatal(err)
	}
	return key
}

func encryptSessionKey(pub *rsa.PublicKey, sessionKey []byte) []byte {
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, sessionKey, nil)
	if err != nil {
		log.Fatal(err)
	}
	return encryptedKey
}

func decryptSessionKey(priv *rsa.PrivateKey, encryptedKey []byte) []byte {
	sessionKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedKey, nil)
	if err != nil {
		log.Fatal(err)
	}
	return sessionKey
}

func encryptMessage(sessionKey []byte, plaintext string) (ciphertext, nonce []byte) {
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		log.Fatal(err)
	}

	nonce = make([]byte, 12)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		log.Fatal(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	ciphertext = aesgcm.Seal(nil, nonce, []byte(plaintext), nil)

	return ciphertext, nonce
}

func decryptMessage(sessionKey, ciphertext, nonce []byte) string {
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		log.Fatal(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal("❌ Déchiffrement échoué – message altéré ou corrompu")
	}

	return string(plaintext)
}
