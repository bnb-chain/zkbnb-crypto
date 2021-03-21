package bp_bn128

import (
	"ZKSneak-crypto/elgamal/bn256/twistedElgamal"
	"encoding/json"
	"github.com/consensys/gurvy/bn256"
	"github.com/consensys/gurvy/bn256/fr"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestXWithinRange(t *testing.T) {
	x := new(fr.Element).SetUint64(3)
	params := setupRange(t, MAX_RANGE_END)
	// commitment to v and gamma
	gamma, _ := new(fr.Element).SetRandom()
	//V, _ := CommitG1(x, gamma, params.H)
	_, pk := twistedElgamal.GenKeyPair()
	C := twistedElgamal.Enc(x, gamma, pk)
	if proveAndVerifyRange(x, gamma, C.CR, params) != true {
		t.Errorf("x within range should verify successfully")
	}
}

func TestJsonEncodeDecode(t *testing.T) {
	params, _ := Setup(MAX_RANGE_END)
	secret := new(fr.Element).SetUint64(18)
	// commitment to v and gamma
	gamma, _ := new(fr.Element).SetRandom()
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

func proveAndVerifyRange(x *fr.Element, gamma *fr.Element, V *bn256.G1Affine, params BulletProofSetupParams) bool {
	proof, _ := Prove(x, gamma, V, params)
	ok, _ := proof.Verify()
	return ok
}
