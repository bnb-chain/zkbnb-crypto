package test

import (
	"encoding/hex"
	"log"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/stretchr/testify/assert"

	curve "github.com/bnb-chain/zkbnb-crypto/ecc/ztwistededwards/tebn254"
)

func TestEddsaPublicKey(t *testing.T) {
	seed := "12345678901234567890123456789012"
	sk, err := curve.GenerateEddsaPrivateKey(seed)

	assert.Nil(t, err)
	log.Println(hex.EncodeToString(sk.PublicKey.Bytes()))
	log.Println(hex.EncodeToString(sk.Bytes()))

	msg := "hello zkbnb"

	hFunc := mimc.NewMiMC()
	signature, err := sk.Sign([]byte(msg), hFunc)
	assert.Nil(t, err)

	ok, err := sk.PublicKey.Verify(signature, []byte(msg), hFunc)
	assert.Nil(t, err)
	assert.True(t, ok)

}
