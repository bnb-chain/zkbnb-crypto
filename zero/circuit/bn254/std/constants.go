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

package std

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"github.com/bnb-chain/zkbas-crypto/rangeProofs/twistededwards/tebn254/ctrange"
	"github.com/bnb-chain/zkbas-crypto/zero/twistededwards/tebn254/zero"
	"math/big"
)

type (
	Point      = twistededwards.Point
	Variable   = frontend.Variable
	API        = frontend.API
	MiMC       = mimc.MiMC
	ElgamalEnc = twistedElgamal.ElGamalEnc
)

const (
	NbTransferCount = 3
	RangeMaxBits    = ctrange.RangeMaxBits

	NbAccountsPerTx           = 4
	NbAccountAssetsPerAccount = 3

	MaxRangeProofCount = 3
)

var (
	HX, _          = new(big.Int).SetString(curve.H.X.String(), 10)
	HY, _          = new(big.Int).SetString(curve.H.Y.String(), 10)
	BasePoint      = curve.G
	ZeroInt        = uint64(0)
	DefaultInt     = int64(-1)
	ZeroBigInt     = big.NewInt(0)
	ZeroElgamalEnc = &ElgamalEnc{CL: BasePoint, CR: BasePoint}
	ZeroPoint      = curve.ZeroPoint()
	FixedCurve     = zero.FixedCurve
)

type PairInfoConstraints struct {
	AssetA  Variable
	AssetAR Variable
	AssetB  Variable
	AssetBR Variable
	LpEnc   ElGamalEncConstraints
}
