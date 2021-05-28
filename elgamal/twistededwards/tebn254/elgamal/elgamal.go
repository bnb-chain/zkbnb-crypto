package elgamal

import (
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
)

var ORDER = curve.Order

type Point = curve.Point

type ElGamalEnc struct {
	CL *Point
	CR *Point
}

func GenKeyPair() (sk *big.Int, pk *Point) {
	sk = curve.RandomValue()
	pk = curve.ScalarBaseMul(sk)
	return sk, pk
}

func EncAdd(C1 *ElGamalEnc, C2 *ElGamalEnc) *ElGamalEnc {
	CL := curve.Add(C1.CL, C2.CL)
	CR := curve.Add(C1.CR, C2.CR)
	return &ElGamalEnc{CL: CL, CR: CR}
}

func (value *ElGamalEnc) Set(enc *ElGamalEnc) {
	value.CL = new(Point).Set(enc.CL)
	value.CR = new(Point).Set(enc.CR)
}

func Enc(b *big.Int, r *big.Int, pk *Point) (*ElGamalEnc) {
	// g^r
	CL := curve.ScalarBaseMul(r)
	// g^b pk^r
	CR := curve.ScalarBaseMul(b)
	CR = curve.Add(CR, curve.ScalarMul(pk, r))
	return &ElGamalEnc{CL: CL, CR: CR}
}

func Dec(enc *ElGamalEnc, sk *big.Int, Max int64) (*big.Int) {
	//  pk^r
	pkExpr := curve.ScalarMul(enc.CL, sk)
	// g^b
	gExpb := curve.Add(enc.CR, curve.Neg(pkExpr))
	for i := int64(0); i < Max; i++ {
		b := big.NewInt(i)
		hi := curve.ScalarBaseMul(b)
		if hi.Equal(gExpb) {
			return b
		}
	}
	return nil
}

func DecByStart(enc *ElGamalEnc, sk *big.Int, start int, Max int64) (*big.Int) {
	//  pk^r
	pkExpr := curve.ScalarMul(enc.CL, sk)
	// g^b
	gExpb := curve.Add(enc.CR, curve.Neg(pkExpr))
	for i := int64(start); i < Max; i++ {
		b := big.NewInt(i)
		hi := curve.ScalarBaseMul(b)
		if hi.Equal(gExpb) {
			return b
		}
	}
	return nil
}
