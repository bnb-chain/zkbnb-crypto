package bp_bn128

import (
	"ZKSneak-crypto/elgamal/twistedElgamal_bn128"
	"crypto/rand"
	"encoding/json"
	"github.com/consensys/gurvy/bn256"
	"github.com/stretchr/testify/assert"
	"math"
	"math/big"
	"testing"
)

func TestXWithinRange(t *testing.T) {
	rangeEnd := int64(math.Pow(2, 32))
	x := new(big.Int).SetInt64(3)
	params := setupRange(t, rangeEnd)
	// commitment to v and gamma
	gamma, _ := rand.Int(rand.Reader, ORDER)
	//V, _ := CommitG1(x, gamma, params.H)
	_, pk := twistedElgamal_bn128.GenKeyPair()
	C := twistedElgamal_bn128.Enc(x, gamma, pk)
	if proveAndVerifyRange(x, gamma, C.CR, params) != true {
		t.Errorf("x within range should verify successfully")
	}
}

func TestJsonEncodeDecode(t *testing.T) {
	params, _ := Setup(MAX_RANGE_END)
	secret := new(big.Int).SetInt64(18)
	// commitment to v and gamma
	gamma, _ := rand.Int(rand.Reader, ORDER)
	V, _ := CommitG1(secret, gamma, params.H)
	proof, _ := Prove(secret, gamma, V, params)
	jsonEncoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal("encode error:", err)
	}

	// network transfer takes place here

	var decodedProof BulletProof
	err = json.Unmarshal(jsonEncoded, &decodedProof)
	if err != nil {
		t.Fatal("decode error:", err)
	}

	assert.Equal(t, proof, decodedProof, "should be equal")

	ok, err := decodedProof.Verify()
	if err != nil {
		t.Fatal("verify error:", err)
	}
	assert.True(t, ok, "should verify")
}

func setupRange(t *testing.T, rangeEnd int64) BulletProofSetupParams {
	params, err := Setup(rangeEnd)
	if err != nil {
		t.Errorf("Invalid range end: %s", err)
		t.FailNow()
	}
	return params
}

func proveAndVerifyRange(x *big.Int, gamma *big.Int, V *bn256.G1Affine, params BulletProofSetupParams) bool {
	proof, _ := Prove(x, gamma, V, params)
	ok, _ := proof.Verify()
	return ok
}
