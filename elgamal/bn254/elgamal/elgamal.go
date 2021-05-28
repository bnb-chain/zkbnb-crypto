package elgamal

import (
	"math/big"
	curve "zecrey-crypto/ecc/zbn254"
)

var ORDER = curve.Order

type Point = curve.G1Affine

type ElGamalEnc struct {
	CL *Point
	CR *Point
}

func GenKeyPair() (sk *big.Int, pk *Point) {
	sk = curve.RandomValue()
	pk = curve.G1ScalarBaseMul(sk)
	return sk, pk
}

func EncAdd(C1 *ElGamalEnc, C2 *ElGamalEnc) *ElGamalEnc {
	CL := curve.G1Add(C1.CL, C2.CL)
	CR := curve.G1Add(C1.CR, C2.CR)
	return &ElGamalEnc{CL: CL, CR: CR}
}

func (value *ElGamalEnc) Set(enc *ElGamalEnc) {
	value.CL = new(Point).Set(enc.CL)
	value.CR = new(Point).Set(enc.CR)
}

func Enc(b *big.Int, r *big.Int, pk *Point) (*ElGamalEnc) {
	// g^r
	CL := curve.G1ScalarBaseMul(r)
	// g^b pk^r
	CR := curve.G1ScalarBaseMul(b)
	CR = curve.G1Add(CR, curve.G1ScalarMul(pk, r))
	return &ElGamalEnc{CL: CL, CR: CR}
}

func Dec(enc *ElGamalEnc, sk *big.Int, Max int64) (*big.Int) {
	//  pk^r
	pkExpr := curve.G1ScalarMul(enc.CL, sk)
	// g^b
	gExpb := curve.G1Add(enc.CR, curve.G1Neg(pkExpr))
	for i := int64(0); i < Max; i++ {
		b := big.NewInt(i)
		hi := curve.G1ScalarBaseMul(b)
		if hi.Equal(gExpb) {
			return b
		}
	}
	return nil
}

func DecByStart(enc *ElGamalEnc, sk *big.Int, start int, Max int64) (*big.Int) {
	//  pk^r
	pkExpr := curve.G1ScalarMul(enc.CL, sk)
	// g^b
	gExpb := curve.G1Add(enc.CR, curve.G1Neg(pkExpr))
	for i := int64(start); i < Max; i++ {
		b := big.NewInt(i)
		hi := curve.G1ScalarBaseMul(b)
		if hi.Equal(gExpb) {
			return b
		}
	}
	return nil
}
