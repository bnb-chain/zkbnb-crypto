/*
 * Copyright © 2022 ZkBNB Protocol
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

package txtypes

import (
	"math"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"

	"github.com/bnb-chain/zkbnb-crypto/util"
)

type (
	Signature  = eddsa.Signature
	PrivateKey = eddsa.PrivateKey
)

const (
	ChainId = 1
)

const (
	NilNonce        = -1
	NilExpiredAt    = math.MaxInt64
	NilAccountIndex = int64(-1)
	NilAssetId      = int64(-1)
)

const (
	TxTypeEmpty = iota
	TxTypeChangePubKey
	TxTypeDeposit
	TxTypeDepositNft
	TxTypeTransfer
	TxTypeWithdraw
	TxTypeCreateCollection
	TxTypeMintNft
	TxTypeTransferNft
	TxTypeAtomicMatch
	TxTypeCancelOffer
	TxTypeWithdrawNft
	TxTypeFullExit
	TxTypeFullExitNft
	TxTypeOffer
	TxTypeUpdateNFT
)

const (
	HashLength int = 32

	l1AddressHashLength int = 20

	minAccountIndex int64 = 0
	maxAccountIndex int64 = (1 << 32) - 1

	minAssetId int64 = 0
	maxAssetId int64 = (1 << 16) - 1

	minNftIndex int64 = 0
	maxNftIndex int64 = (1 << 40) - 1

	minCollectionId int64 = 0
	maxCollectionId int64 = (1 << 16) - 1

	minNonce int64 = 0

	minRate     int64 = 0
	maxRate     int64 = 10000
	maxSellRate int64 = 5000

	minCollectionNameLength int = 1
	maxCollectionNameLength int = 64

	maxCollectionIntroductionLength int = 1000

	maxLength int = 2000

	minNftContentType int64 = 0
	maxNftContentType int64 = (1 << 8) - 1
)

var (
	minPackedFeeAmount = big.NewInt(0)
	maxPackedFeeAmount = util.PackedFeeMaxAmount

	minAssetAmount = big.NewInt(0)
	maxAssetAmount = util.PackedAmountMaxAmount
)
