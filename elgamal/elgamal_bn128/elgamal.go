package elgamal_bn128

import (
	"ZKSneak-crypto/ecc/bn128"
	"crypto/rand"
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

type ElGamalEnc struct {
	CL *bn256.G1Affine
	CR *bn256.G1Affine
}

func GenKeyPair() (sk *big.Int, pk *bn256.G1Affine) {
	sk, _ = rand.Int(rand.Reader, ORDER)
	pk = bn128.G1ScalarBaseMult(sk)
	return sk, pk
}

func EncAdd(C1 *ElGamalEnc, C2 *ElGamalEnc) *ElGamalEnc {
	CL := bn128.G1AffineMul(C1.CL, C2.CL)
	CR := bn128.G1AffineMul(C1.CR, C2.CR)
	return &ElGamalEnc{CL: CL, CR: CR}
}

func (value *ElGamalEnc) Set(enc *ElGamalEnc) {
	value.CL = new(bn256.G1Affine).Set(enc.CL)
	value.CR = new(bn256.G1Affine).Set(enc.CR)
}

func Enc(b *big.Int, r *big.Int, pk *bn256.G1Affine) (*ElGamalEnc) {
	// g^r
	CL := bn128.G1ScalarBaseMult(r)
	// g^b pk^r
	CR := bn128.G1ScalarBaseMult(b)
	CR = bn128.G1AffineMul(CR, new(bn256.G1Affine).ScalarMultiplication(pk, r))
	return &ElGamalEnc{CL: CL, CR: CR}
}

func Dec(enc *ElGamalEnc, sk *big.Int) (*big.Int) {
	//  pk^r
	pkExpr := new(bn256.G1Affine).ScalarMultiplication(enc.CL, sk)
	// g^b
	gExpb := bn128.G1AffineMul(enc.CR, new(bn256.G1Affine).Neg(pkExpr))
	for i := 0; i < MAX_VALUE; i++ {
		hi := bn128.G1ScalarBaseMult(big.NewInt(int64(i)))
		if hi.Equal(gExpb) {
			return big.NewInt(int64(i))
		}
	}
	return nil
}

func DecByStart(enc *ElGamalEnc, sk *big.Int, start int) (*big.Int) {
	//  pk^r
	pkExpr := new(bn256.G1Affine).ScalarMultiplication(enc.CL, sk)
	// g^b
	gExpb := bn128.G1AffineMul(enc.CR, new(bn256.G1Affine).Neg(pkExpr))
	for i := start; i < MAX_VALUE; i++ {
		hi := bn128.G1ScalarBaseMult(big.NewInt(int64(i)))
		if hi.Equal(gExpb) {
			return big.NewInt(int64(i))
		}
	}
	return nil
}
