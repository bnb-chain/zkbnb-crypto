package twistedElgamal_bn128

import (
	"ZKSneak/ZKSneak-crypto/ecc/bn128"
	"ZKSneak/ZKSneak-crypto/ffmath"
	"crypto/rand"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

type ElGamalEnc struct {
	CL *bn256.G1Affine // pk^r
	CR *bn256.G1Affine // g^r h^b
}

func EncAdd(C1 *ElGamalEnc, C2 *ElGamalEnc) *ElGamalEnc {
	CL := bn128.G1AffineMul(C1.CL, C2.CL)
	CR := bn128.G1AffineMul(C1.CR, C2.CR)
	return &ElGamalEnc{CL: CL, CR: CR}
}

func GenKeyPair() (sk *big.Int, pk *bn256.G1Affine) {
	sk, _ = rand.Int(rand.Reader, ORDER)
	pk = bn128.G1ScalarBaseMult(sk)
	return sk, pk
}

func GetPk(sk *big.Int) (pk *bn256.G1Affine) {
	pk = bn128.G1ScalarBaseMult(sk)
	return pk
}

func Enc(b *big.Int, r *big.Int, pk *bn256.G1Affine) (*ElGamalEnc) {
	// pk^r
	CL := new(bn256.G1Affine).ScalarMultiplication(pk, r)
	// g^r h^b
	CR := bn128.G1ScalarBaseMult(r)
	CR = bn128.G1AffineMul(CR, bn128.G1ScalarHBaseMult(b))
	return &ElGamalEnc{CL: CL, CR: CR}
}

func Dec(enc *ElGamalEnc, sk *big.Int) (*big.Int) {
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.ModInverse(sk, ORDER)
	gExpr := new(bn256.G1Affine).ScalarMultiplication(enc.CL, skInv)
	hExpb := bn128.G1AffineMul(enc.CR, new(bn256.G1Affine).Neg(gExpr))
	for i := 0; i < MAX_VALUE; i++ {
		hi := bn128.G1ScalarHBaseMult(big.NewInt(int64(i)))
		if hi.Equal(hExpb) {
			return big.NewInt(int64(i))
		}
	}
	return nil
}

func DecByStart(enc *ElGamalEnc, sk *big.Int, start int) (*big.Int) {
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.ModInverse(sk, ORDER)
	gExpr := new(bn256.G1Affine).ScalarMultiplication(enc.CL, skInv)
	hExpb := bn128.G1AffineMul(enc.CR, new(bn256.G1Affine).Neg(gExpr))
	for i := start; i < MAX_VALUE; i++ {
		hi := bn128.G1ScalarHBaseMult(big.NewInt(int64(i)))
		if hi.Equal(hExpb) {
			return big.NewInt(int64(i))
		}
	}
	return nil
}
