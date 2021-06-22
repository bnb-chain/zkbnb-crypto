package twistedElgamal

import (
	"math/big"
	curve "zecrey-crypto/ecc/zbn254"
	"zecrey-crypto/ffmath"
)

var (
	Order = curve.Order
	G, H  = curve.GetG1TwoBaseAffine()
)

type Point = curve.G1Affine

type ElGamalEnc struct {
	CL *Point // pk^r
	CR *Point // g^r h^b
}

func EncAdd(C1 *ElGamalEnc, C2 *ElGamalEnc) *ElGamalEnc {
	CL := curve.G1Add(C1.CL, C2.CL)
	CR := curve.G1Add(C1.CR, C2.CR)
	return &ElGamalEnc{CL: CL, CR: CR}
}

func GenKeyPair() (sk *big.Int, pk *Point) {
	sk = curve.RandomValue()
	pk = curve.G1ScalarBaseMul(sk)
	return sk, pk
}

func (value *ElGamalEnc) Set(enc *ElGamalEnc) {
	value.CL = new(Point).Set(enc.CL)
	value.CR = new(Point).Set(enc.CR)
}

func Pk(sk *big.Int) (pk *Point) {
	pk = curve.G1ScalarBaseMul(sk)
	return pk
}

func Enc(b *big.Int, r *big.Int, pk *Point) (*ElGamalEnc) {
	// pk^r
	CL := curve.G1ScalarMul(pk, r)
	// g^r h^b
	CR := curve.G1ScalarBaseMul(r)
	CR = curve.G1Add(CR, curve.G1ScalarHBaseMul(b))
	return &ElGamalEnc{CL: CL, CR: CR}
}

func Dec(enc *ElGamalEnc, sk *big.Int, Max int64) (*big.Int) {
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.ModInverse(sk, Order)
	gExpr := curve.G1ScalarMul(enc.CL, skInv)
	hExpb := curve.G1Add(enc.CR, curve.G1Neg(gExpr))
	for i := int64(0); i < Max; i++ {
		b := big.NewInt(int64(i))
		hi := curve.G1ScalarMul(H, b)
		if hi.Equal(hExpb) {
			return b
		}
	}
	return nil
}

func DecByStart(enc *ElGamalEnc, sk *big.Int, start int64, Max int64) (*big.Int) {
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.ModInverse(sk, Order)
	gExpr := curve.G1ScalarMul(enc.CL, skInv)
	hExpb := curve.G1Add(enc.CR, curve.G1Neg(gExpr))
	for i := int64(start); i < Max; i++ {
		b := big.NewInt(int64(i))
		hi := curve.G1ScalarMul(H, b)
		if hi.Equal(hExpb) {
			return b
		}
	}
	return nil
}
