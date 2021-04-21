package twistedElgamal

import (
	"zecrey-crypto/ecc/zbn254"
	"zecrey-crypto/ffmath"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

type ElGamalEnc struct {
	CL *bn256.G1Affine // pk^r
	CR *bn256.G1Affine // g^r h^b
}

func EncAdd(C1 *ElGamalEnc, C2 *ElGamalEnc) *ElGamalEnc {
	CL := zbn254.G1Add(C1.CL, C2.CL)
	CR := zbn254.G1Add(C1.CR, C2.CR)
	return &ElGamalEnc{CL: CL, CR: CR}
}

func GenKeyPair() (sk *big.Int, pk *bn256.G1Affine) {
	sk = zbn254.RandomValue()
	pk = zbn254.G1ScalarBaseMul(sk)
	return sk, pk
}

func (value *ElGamalEnc) Set(enc *ElGamalEnc) {
	value.CL = new(bn256.G1Affine).Set(enc.CL)
	value.CR = new(bn256.G1Affine).Set(enc.CR)
}

func GetPk(sk *big.Int) (pk *bn256.G1Affine) {
	pk = zbn254.G1ScalarBaseMul(sk)
	return pk
}

func Enc(b *big.Int, r *big.Int, pk *bn256.G1Affine) (*ElGamalEnc) {
	// pk^r
	CL := zbn254.G1ScalarMult(pk, r)
	// g^r h^b
	CR := zbn254.G1ScalarBaseMul(r)
	CR = zbn254.G1Add(CR, zbn254.G1ScalarHBaseMult(b))
	return &ElGamalEnc{CL: CL, CR: CR}
}

func Dec(enc *ElGamalEnc, sk *big.Int) (*big.Int) {
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.ModInverse(sk, zbn254.Order)
	gExpr := zbn254.G1ScalarMult(enc.CL, skInv)
	hExpb := zbn254.G1Add(enc.CR, zbn254.G1Neg(gExpr))
	for i := 0; i < MAX_VALUE; i++ {
		hi := zbn254.G1ScalarHBaseMult(big.NewInt(int64(i)))
		if hi.Equal(hExpb) {
			return new(big.Int).SetUint64(uint64(i))
		}
	}
	return nil
}

func DecByStart(enc *ElGamalEnc, sk *big.Int, start int) (*big.Int) {
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.ModInverse(sk, zbn254.Order)
	gExpr := zbn254.G1ScalarMult(enc.CL, skInv)
	hExpb := zbn254.G1Add(enc.CR, zbn254.G1Neg(gExpr))
	for i := start; i < MAX_VALUE; i++ {
		hi := zbn254.G1ScalarHBaseMult(big.NewInt(int64(i)))
		if hi.Equal(hExpb) {
			return new(big.Int).SetUint64(uint64(i))
		}
	}
	return nil
}
