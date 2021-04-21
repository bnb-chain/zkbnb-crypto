package twistedElgamal

import (
	"zecrey-crypto/ecc/zbls381"
	"zecrey-crypto/ffmath"
	"math/big"
)

type G1Affine = zbls381.G1Affine

type ElGamalEnc struct {
	CL *G1Affine // pk^r
	CR *G1Affine // g^r h^b
}

func EncAdd(C1 *ElGamalEnc, C2 *ElGamalEnc) *ElGamalEnc {
	CL := zbls381.G1Add(C1.CL, C2.CL)
	CR := zbls381.G1Add(C1.CR, C2.CR)
	return &ElGamalEnc{CL: CL, CR: CR}
}

func GenKeyPair() (sk *big.Int, pk *G1Affine) {
	sk = zbls381.RandomValue()
	pk = zbls381.G1ScalarBaseMul(sk)
	return sk, pk
}

func (value *ElGamalEnc) Set(enc *ElGamalEnc) {
	value.CL = new(G1Affine).Set(enc.CL)
	value.CR = new(G1Affine).Set(enc.CR)
}

func GetPk(sk *big.Int) (pk *G1Affine) {
	pk = zbls381.G1ScalarBaseMul(sk)
	return pk
}

func Enc(b *big.Int, r *big.Int, pk *G1Affine) (*ElGamalEnc) {
	// pk^r
	CL := zbls381.G1ScalarMul(pk, r)
	// g^r h^b
	CR := zbls381.G1ScalarBaseMul(r)
	CR = zbls381.G1Add(CR, zbls381.G1ScalarHBaseMul(b))
	return &ElGamalEnc{CL: CL, CR: CR}
}

func Dec(enc *ElGamalEnc, sk *big.Int) (*big.Int) {
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.ModInverse(sk, zbls381.Order)
	gExpr := zbls381.G1ScalarMul(enc.CL, skInv)
	hExpb := zbls381.G1Add(enc.CR, zbls381.G1Neg(gExpr))
	for i := 0; i < MAX_VALUE; i++ {
		hi := zbls381.G1ScalarHBaseMul(big.NewInt(int64(i)))
		if hi.Equal(hExpb) {
			return new(big.Int).SetUint64(uint64(i))
		}
	}
	return nil
}

func DecByStart(enc *ElGamalEnc, sk *big.Int, start int) (*big.Int) {
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.ModInverse(sk, zbls381.Order)
	gExpr := zbls381.G1ScalarMul(enc.CL, skInv)
	hExpb := zbls381.G1Add(enc.CR, zbls381.G1Neg(gExpr))
	for i := start; i < MAX_VALUE; i++ {
		hi := zbls381.G1ScalarHBaseMul(big.NewInt(int64(i)))
		if hi.Equal(hExpb) {
			return new(big.Int).SetUint64(uint64(i))
		}
	}
	return nil
}
