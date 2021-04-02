package twistedElgamal

import (
	"PrivaL-crypto/ecc/zp256"
	"PrivaL-crypto/ffmath"
	"math/big"
)

type P256 = zp256.P256

type ElGamalEnc struct {
	CL *P256 // pk^r
	CR *P256 // g^r h^b
}

func EncAdd(C1 *ElGamalEnc, C2 *ElGamalEnc) *ElGamalEnc {
	CL := zp256.Add(C1.CL, C2.CL)
	CR := zp256.Add(C1.CR, C2.CR)
	return &ElGamalEnc{CL: CL, CR: CR}
}

func GenKeyPair() (sk *big.Int, pk *P256) {
	sk = zp256.RandomValue()
	pk = zp256.ScalarBaseMult(sk)
	return sk, pk
}

func (value *ElGamalEnc) Set(enc *ElGamalEnc) {
	value.CL = zp256.Set(enc.CL)
	value.CR = zp256.Set(enc.CR)
}

func GetPk(sk *big.Int) (pk *P256) {
	pk = zp256.ScalarBaseMult(sk)
	return pk
}

func Enc(b *big.Int, r *big.Int, pk *P256) (*ElGamalEnc) {
	// pk^r
	CL := zp256.ScalarMult(pk, r)
	// g^r h^b
	CR := zp256.ScalarBaseMult(r)
	CR = zp256.Add(CR, zp256.ScalarHBaseMult(b))
	return &ElGamalEnc{CL: CL, CR: CR}
}

func Dec(enc *ElGamalEnc, sk *big.Int) (*big.Int) {
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.ModInverse(sk, zp256.Curve.N)
	gExpr := zp256.ScalarMult(enc.CL, skInv)
	hExpb := zp256.Add(enc.CR, zp256.Neg(gExpr))
	for i := 0; i < MAX_VALUE; i++ {
		hi := zp256.ScalarHBaseMult(big.NewInt(int64(i)))
		if zp256.Equal(hi, hExpb) {
			return new(big.Int).SetUint64(uint64(i))
		}
	}
	return nil
}

func DecByStart(enc *ElGamalEnc, sk *big.Int, start int) (*big.Int) {
	// (pk^r)^{sk^{-1}}
	skInv := ffmath.ModInverse(sk, zp256.Curve.N)
	gExpr := zp256.ScalarMult(enc.CL, skInv)
	hExpb := zp256.Add(enc.CR, zp256.Neg(gExpr))
	for i := start; i < MAX_VALUE; i++ {
		hi := zp256.ScalarHBaseMult(big.NewInt(int64(i)))
		if zp256.Equal(hi, hExpb) {
			return new(big.Int).SetUint64(uint64(i))
		}
	}
	return nil
}
