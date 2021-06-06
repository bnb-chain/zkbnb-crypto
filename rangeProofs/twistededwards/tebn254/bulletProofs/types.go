package bulletProofs

import (
	"math/big"
)

/*
BPSetupParams is the structure that stores the parameters for
the Zero Knowledge Proof system.
*/
type BPSetupParams struct {
	// N is the bit-length of the range.
	N int64
	// G is the Elliptic Curve generator.
	G *Point
	// H is a new generator, computed using MapToGroup function,
	// such that there is no discrete logarithm relation with G.
	H *Point
	// Gs and Hs are sets of new generators obtained using MapToGroup.
	// They are used to compute Pedersen Vector Commitments.
	Gs []*Point
	Hs []*Point
	// InnerProductParams is the setup parameters for the inner product proof.
	InnerProductParams *InnerProductParams
}

/*
BulletProofs structure contains the elements that are necessary for the verification
of the Zero Knowledge Proof.
*/
type BulletProof struct {
	V                 *Point
	A                 *Point
	S                 *Point
	T1                *Point
	T2                *Point
	Taux              *big.Int
	Mu                *big.Int
	That              *big.Int
	InnerProductProof *InnerProductProof
	Commit            *Point
	Params            *BPSetupParams
}

/*
BulletProofs structure contains the elements that are necessary for the verification
of the Zero Knowledge Proof.
*/
type AggBulletProof struct {
	Vs                []*Point
	A                 *Point
	S                 *Point
	T1                *Point
	T2                *Point
	Taux              *big.Int
	Mu                *big.Int
	That              *big.Int
	InnerProductProof *InnerProductProof
	Commit            *Point
	Params            *BPSetupParams
}

/*
InnerProductParams contains elliptic curve generators used to compute Pedersen
commitments.
*/
type InnerProductParams struct {
	N  int64
	C  *big.Int
	U  *Point
	H  *Point
	Gs []*Point
	Hs []*Point
	P  *Point
}

/*
InnerProductProof contains the elements used to verify the Inner Product Proof.
*/
type InnerProductProof struct {
	N      int64
	Ls     []*Point
	Rs     []*Point
	U      *Point
	P      *Point
	G      *Point
	H      *Point
	A      *big.Int
	B      *big.Int
	Params *InnerProductParams
}

// params for aggregation proofs
type AggProveParam struct {
	Secret *big.Int
	Gamma  *big.Int
	V      *Point
}
