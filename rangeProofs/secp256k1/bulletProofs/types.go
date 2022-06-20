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
	"github.com/bnb-chain/zkbas-crypto/ecc/zp256"
)

type P256 = zp256.P256

/*
BPSetupParams is the structure that stores the parameters for
the Zero Knowledge Proof system.
*/
type BPSetupParams struct {
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
	Params            *BPSetupParams
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
	Params            *BPSetupParams
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
