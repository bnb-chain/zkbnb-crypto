package test

import (
	"encoding/hex"
	curve "github.com/bnb-chain/zkbnb-crypto/ecc/ztwistededwards/tebn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

func TestEddsaPublicKey(t *testing.T) {
	seed := "12345678901234567890123456789012"
	sk, err := curve.GenerateEddsaPrivateKey(seed)

	assert.Nil(t, err)
	log.Println(hex.EncodeToString(sk.PublicKey.Bytes()))
	log.Println(hex.EncodeToString(sk.Bytes()))

	msg := "hello zecrey legend"

	hFunc := mimc.NewMiMC()
	signature, err := sk.Sign([]byte(msg), hFunc)
	assert.Nil(t, err)

	ok, err := sk.PublicKey.Verify(signature, []byte(msg), hFunc)
	assert.Nil(t, err)
	assert.True(t, ok)

}
