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
	"github.com/bnb-chain/zkbas-crypto/common"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	eddsaConstraints "github.com/consensys/gnark/std/signature/eddsa"
	"math/big"
)

type (
	Variable             = frontend.Variable
	API                  = frontend.API
	MiMC                 = mimc.MiMC
	PublicKeyConstraints = eddsaConstraints.PublicKey
	PublicKey            = eddsa.PublicKey
)

const (
	ZeroInt    = uint64(0)
	OneInt     = uint64(1)
	DefaultInt = int64(-1)

	NbAccountAssetsPerAccount = 4
	NbAccountsPerTx           = 5
	NbAccountEcdsaPkBytes     = 32

	PubDataSizePerTx = 6

	OfferSizePerAsset = 128

	ChainId = common.ChainId
)

const (
	TxTypeEmptyTx = iota
	TxTypeRegisterZns
	TxTypeCreatePair
	TxTypeUpdatePairRate
	TxTypeDeposit
	TxTypeDepositNft
	TxTypeTransfer
	TxTypeSwap
	TxTypeAddLiquidity
	TxTypeRemoveLiquidity
	TxTypeWithdraw
	TxTypeCreateCollection
	TxTypeMintNft
	TxTypeTransferNft
	TxTypeAtomicMatch
	TxTypeCancelOffer
	TxTypeWithdrawNft
	TxTypeFullExit
	TxTypeFullExitNft
)

const (
	RateBase = 10000
)

var (
	EmptyAssetRoot, _ = new(big.Int).SetString("20078765925047610631302921414746503738259000135611824775363050619361913896775", 10)
)
