package elgamal

import (
	"zecrey-crypto/ecc/zbls381"
	"math/big"
)

type G1Affine = zbls381.G1Affine

type ElGamalEnc struct {
	CL *G1Affine
	CR *G1Affine
}

func GenKeyPair() (sk *big.Int, pk *G1Affine) {
	sk = zbls381.RandomValue()
	pk = zbls381.G1ScalarBaseMul(sk)
	return sk, pk
}

func EncAdd(C1 *ElGamalEnc, C2 *ElGamalEnc) *ElGamalEnc {
	CL := zbls381.G1Add(C1.CL, C2.CL)
	CR := zbls381.G1Add(C1.CR, C2.CR)
	return &ElGamalEnc{CL: CL, CR: CR}
}

func (value *ElGamalEnc) Set(enc *ElGamalEnc) {
	value.CL = new(G1Affine).Set(enc.CL)
	value.CR = new(G1Affine).Set(enc.CR)
}

func Enc(b *big.Int, r *big.Int, pk *G1Affine) (*ElGamalEnc) {
	// g^r
	CL := zbls381.G1ScalarBaseMul(r)
	// g^b pk^r
	CR := zbls381.G1ScalarBaseMul(b)
	CR = zbls381.G1Add(CR, zbls381.G1ScalarMul(pk, r))
	return &ElGamalEnc{CL: CL, CR: CR}
}

func Dec(enc *ElGamalEnc, sk *big.Int) (*big.Int) {
	//  pk^r
	pkExpr := zbls381.G1ScalarMul(enc.CL, sk)
	// g^b
	gExpb := zbls381.G1Add(enc.CR, zbls381.G1Neg(pkExpr))
	for i := int64(0); i < MAX_VALUE; i++ {
		hi := zbls381.G1ScalarBaseMul(big.NewInt(i))
		if hi.Equal(gExpb) {
			return big.NewInt(i)
		}
	}
	return nil
}

func DecByStart(enc *ElGamalEnc, sk *big.Int, start int) (*big.Int) {
	//  pk^r
	pkExpr := zbls381.G1ScalarMul(enc.CL, sk)
	// g^b
	gExpb := zbls381.G1Add(enc.CR, zbls381.G1Neg(pkExpr))
	for i := int64(start); i < MAX_VALUE; i++ {
		hi := zbls381.G1ScalarBaseMul(big.NewInt(i))
		if hi.Equal(gExpb) {
			return big.NewInt(i)
		}
	}
	return nil
}
