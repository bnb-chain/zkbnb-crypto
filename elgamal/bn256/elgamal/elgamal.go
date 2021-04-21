package elgamal

import (
	"zecrey-crypto/ecc/zbn254"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

type ElGamalEnc struct {
	CL *bn256.G1Affine
	CR *bn256.G1Affine
}

func GenKeyPair() (sk *big.Int, pk *bn256.G1Affine) {
	sk = zbn254.RandomValue()
	pk = zbn254.G1ScalarBaseMul(sk)
	return sk, pk
}

func EncAdd(C1 *ElGamalEnc, C2 *ElGamalEnc) *ElGamalEnc {
	CL := zbn254.G1Add(C1.CL, C2.CL)
	CR := zbn254.G1Add(C1.CR, C2.CR)
	return &ElGamalEnc{CL: CL, CR: CR}
}

func (value *ElGamalEnc) Set(enc *ElGamalEnc) {
	value.CL = new(bn256.G1Affine).Set(enc.CL)
	value.CR = new(bn256.G1Affine).Set(enc.CR)
}

func Enc(b *big.Int, r *big.Int, pk *bn256.G1Affine) (*ElGamalEnc) {
	// g^r
	CL := zbn254.G1ScalarBaseMul(r)
	// g^b pk^r
	CR := zbn254.G1ScalarBaseMul(b)
	CR = zbn254.G1Add(CR, zbn254.G1ScalarMult(pk, r))
	return &ElGamalEnc{CL: CL, CR: CR}
}

func Dec(enc *ElGamalEnc, sk *big.Int) (*big.Int) {
	//  pk^r
	pkExpr := zbn254.G1ScalarMult(enc.CL, sk)
	// g^b
	gExpb := zbn254.G1Add(enc.CR, zbn254.G1Neg(pkExpr))
	for i := int64(0); i < MAX_VALUE; i++ {
		hi := zbn254.G1ScalarBaseMul(big.NewInt(i))
		if hi.Equal(gExpb) {
			return big.NewInt(i)
		}
	}
	return nil
}

func DecByStart(enc *ElGamalEnc, sk *big.Int, start int) (*big.Int) {
	//  pk^r
	pkExpr := zbn254.G1ScalarMult(enc.CL, sk)
	// g^b
	gExpb := zbn254.G1Add(enc.CR, zbn254.G1Neg(pkExpr))
	for i := int64(start); i < MAX_VALUE; i++ {
		hi := zbn254.G1ScalarBaseMul(big.NewInt(i))
		if hi.Equal(gExpb) {
			return big.NewInt(i)
		}
	}
	return nil
}
