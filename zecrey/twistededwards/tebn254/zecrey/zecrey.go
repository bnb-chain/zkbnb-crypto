package zecrey

import (
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/ffmath"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/bulletProofs"
)

func Setup(N, M int64) (*ZSetupParams, error) {
	bpSetupParams, err := bulletProofs.Setup(N, M)
	if err != nil {
		return nil, err
	}
	return &ZSetupParams{bpSetupParams}, nil
}

/**
commit phase for R_{ValidEnc} = {C_L = pk^r \wedge C_R = g^r h^{b}}
@pk: public key
@g: generator
@h: generator
*/
func commitValidEnc(pk, g, h *Point) (
	alpha_r, alpha_bDelta *big.Int, A_CLDelta, A_CRDelta *Point,
) {
	alpha_r = curve.RandomValue()
	alpha_bDelta = curve.RandomValue()
	A_CLDelta = curve.ScalarMul(pk, alpha_r)
	A_CRDelta = curve.Add(curve.ScalarMul(g, alpha_r), curve.ScalarMul(h, alpha_bDelta))
	return
}

func respondValidEnc(r, bDelta, alpha_r, alpha_bDelta, c *big.Int) (
	z_r, z_bDelta *big.Int,
) {
	z_r = ffmath.AddMod(alpha_r, ffmath.Multiply(c, r), Order)
	z_bDelta = ffmath.AddMod(alpha_bDelta, ffmath.Multiply(c, bDelta), Order)
	return
}

func verifyValidEnc(
	pk, C_LDelta, A_CLDelta, g, h, C_RDelta, A_CRDelta *Point,
	c *big.Int,
	z_r, z_bDelta *big.Int,
) (bool, error) {
	if pk == nil || C_LDelta == nil || A_CLDelta == nil || g == nil ||
		h == nil || C_RDelta == nil || A_CRDelta == nil || c == nil ||
		z_r == nil || z_bDelta == nil {
		return false, ErrInvalidParams
	}
	l1 := curve.ScalarMul(pk, z_r)
	r1 := curve.Add(A_CLDelta, curve.ScalarMul(C_LDelta, c))
	if !l1.Equal(r1) {
		return false, nil
	}
	l2 := curve.Add(curve.ScalarMul(g, z_r), curve.ScalarMul(h, z_bDelta))
	r2 := curve.Add(A_CRDelta, curve.ScalarMul(C_RDelta, c))
	return l2.Equal(r2), nil
}

func provePt(alpha_zsk, sk *big.Int, Ht *Point, c *big.Int) (
	A_Pt *Point, z_tsk *big.Int,
) {
	if alpha_zsk == nil {
		alpha_zsk = curve.RandomValue()
	}
	A_Pt = curve.ScalarMul(Ht, alpha_zsk)
	z_tsk = ffmath.Add(alpha_zsk, ffmath.Multiply(c, sk))
	return
}

func verifyPt(
	Ht, Pt, A_Pt *Point,
	c *big.Int,
	z_tsk *big.Int,
) (bool, error) {
	if Ht == nil || Pt == nil || c == nil || z_tsk == nil {
		return false, ErrInvalidParams
	}
	l := curve.ScalarMul(Ht, z_tsk)
	r := curve.Add(A_Pt, curve.ScalarMul(Pt, c))
	return l.Equal(r), nil
}
