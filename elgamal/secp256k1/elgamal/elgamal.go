package elgamal

import (
	"ZKSneak-crypto/ecc/zp256"
	"math/big"
)

type P256 = zp256.P256

type ElGamalEnc struct {
	CL *P256
	CR *P256
}

func GenKeyPair() (sk *big.Int, pk *P256) {
	sk = zp256.RandomValue()
	pk = zp256.ScalarBaseMult(sk)
	return sk, pk
}

func EncAdd(C1 *ElGamalEnc, C2 *ElGamalEnc) *ElGamalEnc {
	CL := zp256.Add(C1.CL, C2.CL)
	CR := zp256.Add(C1.CR, C2.CR)
	return &ElGamalEnc{CL: CL, CR: CR}
}

func (value *ElGamalEnc) Set(enc *ElGamalEnc) {
	value.CL = zp256.Set(enc.CL)
	value.CR = zp256.Set(enc.CR)
}

func Enc(b *big.Int, r *big.Int, pk *P256) (*ElGamalEnc) {
	// g^r
	CL := zp256.ScalarBaseMult(r)
	// g^b pk^r
	CR := zp256.ScalarBaseMult(b)
	CR = zp256.Add(CR, zp256.ScalarMult(pk, r))
	return &ElGamalEnc{CL: CL, CR: CR}
}

func Dec(enc *ElGamalEnc, sk *big.Int) (*big.Int) {
	//  pk^r
	pkExpr := zp256.ScalarMult(enc.CL, sk)
	// g^b
	gExpb := zp256.Add(enc.CR, zp256.Neg(pkExpr))
	for i := int64(0); i < MAX_VALUE; i++ {
		hi := zp256.ScalarBaseMult(big.NewInt(i))
		if zp256.Equal(hi, gExpb) {
			return big.NewInt(i)
		}
	}
	return nil
}

func DecByStart(enc *ElGamalEnc, sk *big.Int, start int) (*big.Int) {
	//  pk^r
	pkExpr := zp256.ScalarMult(enc.CL, sk)
	// g^b
	gExpb := zp256.Add(enc.CR, zp256.Neg(pkExpr))
	for i := int64(start); i < MAX_VALUE; i++ {
		hi := zp256.ScalarBaseMult(big.NewInt(i))
		if zp256.Equal(hi, gExpb) {
			return big.NewInt(i)
		}
	}
	return nil
}
