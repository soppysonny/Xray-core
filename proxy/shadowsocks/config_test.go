package shadowsocks_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"golang.org/x/crypto/chacha20"
)

func TestAEADCipherUDP(t *testing.T) {
	rawAccount := &shadowsocks.Account{
		CipherType: shadowsocks.CipherType_AES_128_GCM,
		Password:   "test",
	}
	account, err := rawAccount.AsAccount()
	common.Must(err)

	cipher := account.(*shadowsocks.MemoryAccount).Cipher

	key := make([]byte, cipher.KeySize())
	common.Must2(rand.Read(key))

	payload := make([]byte, 1024)
	common.Must2(rand.Read(payload))

	b1 := buf.New()
	common.Must2(b1.ReadFullFrom(rand.Reader, cipher.IVSize()))
	common.Must2(b1.Write(payload))
	common.Must(cipher.EncodePacket(key, b1))

	common.Must(cipher.DecodePacket(key, b1))
	if diff := cmp.Diff(b1.Bytes(), payload); diff != "" {
		t.Error(diff)
	}
}

func TestStreamCipher_Chacha20IETF(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32字节
	iv := []byte("123456789012")                      // 12字节
	plain := []byte("hello, chacha20-ietf test!")

	stream, err := chacha20.NewUnauthenticatedCipher(key, iv)
	if err != nil {
		t.Fatalf("NewUnauthenticatedCipher error: %v", err)
	}
	ciphertext := make([]byte, len(plain))
	stream.XORKeyStream(ciphertext, plain)

	// 解密
	stream2, err := chacha20.NewUnauthenticatedCipher(key, iv)
	if err != nil {
		t.Fatalf("NewUnauthenticatedCipher error: %v", err)
	}
	plaintext := make([]byte, len(ciphertext))
	stream2.XORKeyStream(plaintext, ciphertext)

	if !bytes.Equal(plain, plaintext) {
		t.Errorf("chacha20-ietf decrypt not match, got %s, want %s", plaintext, plain)
	}
}
