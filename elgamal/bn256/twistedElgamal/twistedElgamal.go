package twistedElgamal

import (
	"PrivaL-crypto/ecc/zbn256"
	"PrivaL-crypto/ffmath"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

type ElGamalEnc struct {
	CL *bn256.G1Affine // pk^r
	CR *bn256.G1Affine // g^r h^b
}

func EncAdd(C1 *ElGamalEnc, C2 *ElGamalEnc) *ElGamalEnc {
	CL := zbn256.G1Add(C1.CL, C2.CL)
	CR := zbn256.G1Add(C1.CR, C2.CR)
	return &ElGamalEnc{CL: CL, CR: CR}
}

func GenKeyPair() (sk *big.Int, pk *bn256.G1Affine) {
	sk = zbn256.RandomValue()
	pk = zbn256.G1ScalarBaseMult(sk)
	return sk, pk
}

func (value *ElGamalEnc) Set(enc *ElGamalEnc) {
	value.CL = new(bn256.G1Affine).Set(enc.CL)
	value.CR = new(bn256.G1Affine).Set(enc.CR)
}

func GetPk(sk *big.Int) (pk *bn256.G1Affine) {
	pk = zbn256.G1ScalarBaseMult(sk)
	return pk
}

func Enc(b *big.Int, r *big.Int, pk *bn256.G1Affine) (*ElGamalEnc) {
	// pk^r
	CL := zbn256.G1ScalarMult(pk, r)
	// g^r h^b
	CR := zbn256.G1ScalarBaseMult(r)
	CR = zbn256.G1Add(CR, zbn256.G1ScalarHBaseMult(b))
	return &ElGamalEnc{CL: CL, CR: CR}
}

func Dec(enc *ElGamalEnc, sk *big.Int) (*big.Int) {
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.ModInverse(sk, zbn256.Order)
	gExpr := zbn256.G1ScalarMult(enc.CL, skInv)
	hExpb := zbn256.G1Add(enc.CR, zbn256.G1Neg(gExpr))
	for i := 0; i < MAX_VALUE; i++ {
		hi := zbn256.G1ScalarHBaseMult(big.NewInt(int64(i)))
		if hi.Equal(hExpb) {
			return new(big.Int).SetUint64(uint64(i))
		}
	}
	return nil
}

func DecByStart(enc *ElGamalEnc, sk *big.Int, start int) (*big.Int) {
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.ModInverse(sk, zbn256.Order)
	gExpr := zbn256.G1ScalarMult(enc.CL, skInv)
	hExpb := zbn256.G1Add(enc.CR, zbn256.G1Neg(gExpr))
	for i := start; i < MAX_VALUE; i++ {
		hi := zbn256.G1ScalarHBaseMult(big.NewInt(int64(i)))
		if hi.Equal(hExpb) {
			return new(big.Int).SetUint64(uint64(i))
		}
	}
	return nil
}
