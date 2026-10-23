// Cross-language parity: 14 operations (P1-P14), Go stdlib + x/crypto.
package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

func main() {
	msg := []byte("parity")

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)                                // P1
	p2, _ := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, sha256sum(msg))  // P2
	p3, _ := rsa.EncryptOAEP(sha1.New(), rand.Reader, &rsaKey.PublicKey, msg, nil) // P3 (OAEP)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)                    // P4
	p4, _ := ecdsa.SignASN1(rand.Reader, ecKey, sha256sum(msg))                    // P4
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)                           // P5
	p5 := ed25519.Sign(edPriv, msg)                                                // P5

	gcmBlock, _ := aes.NewCipher(make([]byte, 32)) // P6 SAFE
	gcm, _ := cipher.NewGCM(gcmBlock)
	p6 := gcm.Seal(nil, make([]byte, 12), msg, nil)
	ecbBlock, _ := aes.NewCipher(make([]byte, 16)) // P7 WEAK (ECB)
	p7 := make([]byte, 16)
	ecbBlock.Encrypt(p7, make([]byte, 16))
	desBlock, _ := des.NewTripleDESCipher(make([]byte, 24)) // P8
	p8 := cipher.NewCBCEncrypter(desBlock, make([]byte, 8))
	aead, _ := chacha20poly1305.New(make([]byte, 32)) // P9 SAFE
	p9 := aead.Seal(nil, make([]byte, 12), msg, nil)
	p10 := md5.Sum(msg)                            // P10
	p11 := sha1.Sum(msg)                           // P11
	mac := hmac.New(sha1.New, []byte("test-only")) // P12
	mac.Write(msg)
	p13 := pbkdf2.Key([]byte("pw"), []byte("salt"), 1000, 32, sha1.New) // P13

	fmt.Println(len(p2), len(p3), len(p4), p5 != nil, edPub != nil, len(p6), p7, p8 != nil, len(p9), p10, p11, mac.Sum(nil), p13)
}

func sha256sum(b []byte) []byte { h := make([]byte, 32); copy(h, b); return h }
