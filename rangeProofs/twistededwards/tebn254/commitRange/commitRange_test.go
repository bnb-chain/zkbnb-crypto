package commitRange

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"
	"zecrey-crypto/commitment/twistededwards/tebn254/pedersen"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/util"
)

func TestProveAndVerify(t *testing.T) {
	b := big.NewInt(0)
	r := curve.RandomValue()
	g := curve.H
	h := curve.G
	proof, err := Prove(b, r, g, h, 32)
	if err != nil {
		t.Fatal(err)
	}
	res, err := proof.Verify()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(res)
}

func TestProveCommitmentSameValue(t *testing.T) {
	b := big.NewInt(5)
	r1 := curve.RandomValue()
	r2 := curve.RandomValue()
	g := curve.H
	h := curve.G
	T, _ := pedersen.Commit(b, r1, g, h)
	Tprime, _ := pedersen.Commit(b, r2, g, h)
	A_T, A_Tprime, alpha_b, alpha_r, alpha_rprime, _ := commitCommitmentSameValue(g, h)
	var buf bytes.Buffer
	buf.Write(g.Marshal())
	buf.Write(h.Marshal())
	buf.Write(A_T.Marshal())
	buf.Write(A_Tprime.Marshal())
	c, _ := util.HashToInt(buf, zmimc.Hmimc)
	zb, zr, zrprime, _ := respondCommitmentSameValue(b, r1, r2, alpha_b, alpha_r, alpha_rprime, c)
	res, _ := verifyCommitmentSameValue(A_T, A_Tprime, T, Tprime, g, h, zb, zr, zrprime, c)
	fmt.Println(res)
}
