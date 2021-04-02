package elgamal

import (
	"PrivaL-crypto/ecc/zbls377"
	"math/big"
)

type G1Affine = zbls377.G1Affine

type ElGamalEnc struct {
	CL *G1Affine
	CR *G1Affine
}

func GenKeyPair() (sk *big.Int, pk *G1Affine) {
	sk = zbls377.RandomValue()
	pk = zbls377.G1ScalarBaseMult(sk)
	return sk, pk
}

func EncAdd(C1 *ElGamalEnc, C2 *ElGamalEnc) *ElGamalEnc {
	CL := zbls377.G1Add(C1.CL, C2.CL)
	CR := zbls377.G1Add(C1.CR, C2.CR)
	return &ElGamalEnc{CL: CL, CR: CR}
}

func (value *ElGamalEnc) Set(enc *ElGamalEnc) {
	value.CL = new(G1Affine).Set(enc.CL)
	value.CR = new(G1Affine).Set(enc.CR)
}

func Enc(b *big.Int, r *big.Int, pk *G1Affine) (*ElGamalEnc) {
	// g^r
	CL := zbls377.G1ScalarBaseMult(r)
	// g^b pk^r
	CR := zbls377.G1ScalarBaseMult(b)
	CR = zbls377.G1Add(CR, zbls377.G1ScalarMult(pk, r))
	return &ElGamalEnc{CL: CL, CR: CR}
}

func Dec(enc *ElGamalEnc, sk *big.Int) (*big.Int) {
	//  pk^r
	pkExpr := zbls377.G1ScalarMult(enc.CL, sk)
	// g^b
	gExpb := zbls377.G1Add(enc.CR, zbls377.G1Neg(pkExpr))
	for i := int64(0); i < MAX_VALUE; i++ {
		hi := zbls377.G1ScalarBaseMult(big.NewInt(i))
		if hi.Equal(gExpb) {
			return big.NewInt(i)
		}
	}
	return nil
}

func DecByStart(enc *ElGamalEnc, sk *big.Int, start int) (*big.Int) {
	//  pk^r
	pkExpr := zbls377.G1ScalarMult(enc.CL, sk)
	// g^b
	gExpb := zbls377.G1Add(enc.CR, zbls377.G1Neg(pkExpr))
	for i := int64(start); i < MAX_VALUE; i++ {
		hi := zbls377.G1ScalarBaseMult(big.NewInt(i))
		if hi.Equal(gExpb) {
			return big.NewInt(i)
		}
	}
	return nil
}
