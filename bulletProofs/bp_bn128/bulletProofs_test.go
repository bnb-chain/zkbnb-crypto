package bp_bn128

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"math"
	"math/big"
	"testing"
)

func TestXWithinRange(t *testing.T) {
	rangeEnd := int64(math.Pow(2, 32))
	x := new(big.Int).SetInt64(3)

	params := setupRange(t, rangeEnd)
	if proveAndVerifyRange(x, params) != true {
		t.Errorf("x within range should verify successfully")
	}
}

const MAX_RANGE_END = 4294967296

func TestJsonEncodeDecode(t *testing.T) {
	params, _ := Setup(MAX_RANGE_END)
	proof, _ := Prove(new(big.Int).SetInt64(18), params)
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

func proveAndVerifyRange(x *big.Int, params BulletProofSetupParams) bool {
	proof, _ := Prove(x, params)
	ok, _ := proof.Verify()
	return ok
}