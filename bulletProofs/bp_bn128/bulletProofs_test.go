package bp_bn128

import (
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