package bp_bn128

import (
	"github.com/consensys/gurvy/bn256"
	"github.com/consensys/gurvy/bn256/fr"
)

/*
InnerProductParams contains elliptic curve generators used to compute Pedersen
commitments.
*/
type InnerProductParams struct {
	N  int64
	Cc *fr.Element
	Uu *bn256.G1Affine
	H  *bn256.G1Affine
	Gg []*bn256.G1Affine
	Hh []*bn256.G1Affine
	P  *bn256.G1Affine
}

/*
InnerProductProof contains the elements used to verify the Inner Product Proof.
*/
type InnerProductProof struct {
	N      int64
	Ls     []*bn256.G1Affine
	U      *bn256.G1Affine
	P      *bn256.G1Affine
	Gg     *bn256.G1Affine
	Hh     *bn256.G1Affine
	Rs     []*bn256.G1Affine
	A      *fr.Element
	B      *fr.Element
	Params InnerProductParams
}

/*
BulletProofSetupParams is the structure that stores the parameters for
the Zero Knowledge Proof system.
*/
type BulletProofSetupParams struct {
	// N is the bit-length of the range.
	N int64
	// G is the Elliptic Curve generator.
	G *bn256.G1Affine
	// H is a new generator, computed using MapToGroup function,
	// such that there is no discrete logarithm relation with G.
	H *bn256.G1Affine
	// Gg and Hh are sets of new generators obtained using MapToGroup.
	// They are used to compute Pedersen Vector Commitments.
	Gg []*bn256.G1Affine
	Hh []*bn256.G1Affine
	// InnerProductParams is the setup parameters for the inner product proof.
	InnerProductParams InnerProductParams
}

/*
BulletProofs structure contains the elements that are necessary for the verification
of the Zero Knowledge Proof.
*/
type BulletProof struct {
	V                 *bn256.G1Affine
	A                 *bn256.G1Affine
	S                 *bn256.G1Affine
	T1                *bn256.G1Affine
	T2                *bn256.G1Affine
	Taux              *fr.Element
	Mu                *fr.Element
	Tprime            *fr.Element
	InnerProductProof InnerProductProof
	Commit            *bn256.G1Affine
	Params            BulletProofSetupParams
}
