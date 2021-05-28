package twistedElgamal

import (
	"zecrey-crypto/ecc/zbn254"
	"encoding/json"
	"fmt"
	"github.com/magiconair/properties/assert"
	"math/big"
	"testing"
)

func TestEncDec(t *testing.T) {
	sk, pk := GenKeyPair()
	fmt.Println("pk len:", len(pk.Bytes()))
	b := big.NewInt(100000)
	r := zbn254.RandomValue()
	enc := Enc(b, r, pk)
	encBytes, _ := json.Marshal(enc)
	fmt.Println("encBytes:", encBytes)
	var decodeEnc ElGamalEnc
	err := json.Unmarshal(encBytes, &decodeEnc)
	if err != nil {
		panic(err)
	}
	//dec := Dec(enc, sk)
	dec2 := DecByStart(&decodeEnc, sk, 0)
	//assert.Equal(t, b, dec)
	assert.Equal(t, b, dec2)
}
