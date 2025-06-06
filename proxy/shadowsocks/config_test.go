package shadowsocks_test

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/proxy/shadowsocks"
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

func TestShadowsocksCipher_Chacha20IETF(t *testing.T) {
	rawAccount := &shadowsocks.Account{
		CipherType: shadowsocks.CipherType_CHACHA20_IETF,
		Password:   "testpassword",
	}
	account, err := rawAccount.AsAccount()
	common.Must(err)

	ssCipher := account.(*shadowsocks.MemoryAccount).Cipher

	key := make([]byte, ssCipher.KeySize())
	common.Must2(rand.Read(key))
	iv := make([]byte, ssCipher.IVSize())
	common.Must2(rand.Read(iv))

	plain := []byte("hello, chacha20-ietf test!")

	// 加密
	encStream, err := ssCipher.(*shadowsocks.StreamCipher).NewCipherFunc(key, iv)
	common.Must(err)
	var encBuf bytes.Buffer
	writer := &cipher.StreamWriter{S: encStream, W: &encBuf}
	_, err = writer.Write(plain)
	common.Must(err)

	// 解密
	decStream, err := ssCipher.(*shadowsocks.StreamCipher).NewCipherFunc(key, iv)
	common.Must(err)
	reader := &cipher.StreamReader{S: decStream, R: &encBuf}
	decPlain := make([]byte, len(plain))
	_, err = io.ReadFull(reader, decPlain)
	common.Must(err)

	if !bytes.Equal(plain, decPlain) {
		t.Errorf("chacha20-ietf decrypt not match, got %s, want %s", decPlain, plain)
	}
}
