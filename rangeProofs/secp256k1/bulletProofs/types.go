package bulletProofs

import (
	"ZKSneak-crypto/ecc/zp256"
	"math/big"
)

type P256 = zp256.P256

/*
BulletProofSetupParams is the structure that stores the parameters for
the Zero Knowledge Proof system.
*/
type BulletProofSetupParams struct {
	// N is the bit-length of the range.
	N int64
	// G is the Elliptic Curve generator.
	G *P256
	// H is a new generator, computed using MapToGroup function,
	// such that there is no discrete logarithm relation with G.
	H *P256
	// Gs and Hs are sets of new generators obtained using MapToGroup.
	// They are used to compute Pedersen Vector Commitments.
	Gs []*P256
	Hs []*P256
	// InnerProductParams is the setup parameters for the inner product proof.
	InnerProductParams *InnerProductParams
}

/*
BulletProofs structure contains the elements that are necessary for the verification
of the Zero Knowledge Proof.
*/
type BulletProof struct {
	V                 *P256
	A                 *P256
	S                 *P256
	T1                *P256
	T2                *P256
	Taux              *big.Int
	Mu                *big.Int
	That              *big.Int
	InnerProductProof *InnerProductProof
	Commit            *P256
	Params            *BulletProofSetupParams
}

/*
BulletProofs structure contains the elements that are necessary for the verification
of the Zero Knowledge Proof.
*/
type AggBulletProof struct {
	Vs                []*P256
	A                 *P256
	S                 *P256
	T1                *P256
	T2                *P256
	Taux              *big.Int
	Mu                *big.Int
	That              *big.Int
	InnerProductProof *InnerProductProof
	Commit            *P256
	Params            *BulletProofSetupParams
}

/*
InnerProductParams contains elliptic curve generators used to compute Pedersen
commitments.
*/
type InnerProductParams struct {
	N  int64
	C  *big.Int
	U  *P256
	H  *P256
	Gs []*P256
	Hs []*P256
	P  *P256
}

/*
InnerProductProof contains the elements used to verify the Inner Product Proof.
*/
type InnerProductProof struct {
	N      int64
	Ls     []*P256
	Rs     []*P256
	U      *P256
	P      *P256
	G      *P256
	H      *P256
	A      *big.Int
	B      *big.Int
	Params *InnerProductParams
}

// params for aggregation proofs
type AggProveParam struct {
	Secret *big.Int
	Gamma  *big.Int
	V      *P256
}
