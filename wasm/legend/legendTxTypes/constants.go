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

package legendTxTypes

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"

	"github.com/bnb-chain/zkbas-crypto/common"
	"github.com/bnb-chain/zkbas-crypto/util"
)

type (
	Signature  = eddsa.Signature
	PrivateKey = eddsa.PrivateKey
)

var (
	ZeroBigInt = big.NewInt(0)
	ChainId    = int64(common.ChainId)
)

const (
	HashLength int = 32

	minAccountIndex int64 = 0
	maxAccountIndex int64 = (1 << 32) - 1

	minAssetId int64 = 0
	maxAssetId int64 = (1 << 16) - 1

	minNftIndex int64 = 1
	maxNftIndex int64 = (1 << 40) - 1

	minCollectionId int64 = 1
	maxCollectionId int64 = (1 << 16) - 1

	minNonce int64 = 1

	minTreasuryRate int64 = 0
	maxTreasuryRate int64 = (1 << 16) - 1

	minCollectionNameLength int = 1
	maxCollectionNameLength int = 50

	maxCollectionIntroductionLength int = 1000

	minBlockHeight uint64 = 0
	maxBlockHeight uint64 = (1 << 64) - 1

	minHashLength = 20
	maxHashLength = 100

	minPublicKeyLength = 20
	maxPublicKeyLength = 50

	maxAccountNameLength          = 30
	maxAccountNameLengthOmitSpace = 20

	minPairIndex = 0
	maxPairIndex = (1 << 16) - 1

	minLimit = 0
	maxLimit = 50

	minOffset = 0
	maxOffset = (1 << 64) - 1

	minTxType = 0
	maxTxType = 15

	minLPAmount uint64 = 0
	maxLPAmount uint64 = (1 << 64) - 1

	minGasFee = 0
	maxGasFee = (1 << 64) - 1
)

var (
	minPackedFeeAmount = big.NewInt(0)
	maxPackedFeeAmount = util.PackedFeeMaxAmount

	minAssetAmount = big.NewInt(0)
	maxAssetAmount = util.PackedAmountMaxAmount
)
