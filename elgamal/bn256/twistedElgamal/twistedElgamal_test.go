package twistedElgamal

import (
	"encoding/json"
	"fmt"
	"github.com/consensys/gurvy/bn256/fr"
	"github.com/magiconair/properties/assert"
	"testing"
)

func TestEncDec(t *testing.T) {
	sk, pk := GenKeyPair()
	fmt.Println("pk len:", len(pk.Bytes()))
	b := new(fr.Element).SetUint64(100000)
	r, _ := new(fr.Element).SetRandom()
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
