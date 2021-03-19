package twistedElgamal

import (
	"ZKSneak-crypto/ecc/zbn256"
	"ZKSneak-crypto/math/bn256/ffmath"
	"github.com/consensys/gurvy/bn256"
	"github.com/consensys/gurvy/bn256/fr"
	"math/big"
)

type ElGamalEnc struct {
	CL *bn256.G1Affine // pk^r
	CR *bn256.G1Affine // g^r h^b
}

func EncAdd(C1 *ElGamalEnc, C2 *ElGamalEnc) *ElGamalEnc {
	CL := zbn256.G1AffineMul(C1.CL, C2.CL)
	CR := zbn256.G1AffineMul(C1.CR, C2.CR)
	return &ElGamalEnc{CL: CL, CR: CR}
}

func GenKeyPair() (sk *fr.Element, pk *bn256.G1Affine) {
	sk, _ = new(fr.Element).SetRandom()
	pk = zbn256.G1ScalarBaseMult(sk)
	return sk, pk
}

func (value *ElGamalEnc) Set(enc *ElGamalEnc) {
	value.CL = new(bn256.G1Affine).Set(enc.CL)
	value.CR = new(bn256.G1Affine).Set(enc.CR)
}

func GetPk(sk *fr.Element) (pk *bn256.G1Affine) {
	pk = zbn256.G1ScalarBaseMult(sk)
	return pk
}

func Enc(b *fr.Element, r *fr.Element, pk *bn256.G1Affine) (*ElGamalEnc) {
	// pk^r
	CL := zbn256.G1ScalarMult(pk, r)
	// g^r h^b
	CR := zbn256.G1ScalarBaseMult(r)
	CR = zbn256.G1AffineMul(CR, zbn256.G1ScalarHBaseMult(b))
	return &ElGamalEnc{CL: CL, CR: CR}
}

func Dec(enc *ElGamalEnc, sk *fr.Element) (*fr.Element) {
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.Inverse(sk)
	gExpr := zbn256.G1ScalarMult(enc.CL, skInv)
	hExpb := zbn256.G1AffineMul(enc.CR, new(bn256.G1Affine).Neg(gExpr))
	for i := 0; i < MAX_VALUE; i++ {
		hi := zbn256.G1ScalarBaseMultInt(big.NewInt(int64(i)))
		if hi.Equal(hExpb) {
			return new(fr.Element).SetUint64(uint64(i))
		}
	}
	return nil
}

func DecByStart(enc *ElGamalEnc, sk *fr.Element, start int) (*fr.Element) {
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.Inverse(sk)
	gExpr := zbn256.G1ScalarMult(enc.CL, skInv)
	hExpb := zbn256.G1AffineMul(enc.CR, new(bn256.G1Affine).Neg(gExpr))
	for i := start; i < MAX_VALUE; i++ {
		hi := zbn256.G1ScalarHBaseMultInt(big.NewInt(int64(i)))
		if hi.Equal(hExpb) {
			return new(fr.Element).SetUint64(uint64(i))
		}
	}
	return nil
}
