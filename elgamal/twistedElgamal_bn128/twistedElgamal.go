package twistedElgamal_bn128

import (
	"github.com/consensys/gurvy/bn256"
	"math/big"
)

type ElGamalEnc struct {
	CL *bn256.G1Affine // pk^r
	CR *bn256.G1Affine // g^r h^b
}

func Enc(b *big.Int, pk *bn256.G1Affine) {

}

func Dec() {

}
