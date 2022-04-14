/*
 * Copyright © 2021 Zecrey Protocol
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

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
