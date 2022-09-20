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

package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	eddsaConstraints "github.com/consensys/gnark/std/signature/eddsa"

	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
)

type (
	Variable = frontend.Variable

	Signature            = eddsa.Signature
	SignatureConstraints = eddsaConstraints.Signature
	API                  = frontend.API
	MiMC                 = mimc.MiMC

	RegisterZnsTx      = types.RegisterZnsTx
	CreatePairTx       = types.CreatePairTx
	UpdatePairRateTx   = types.UpdatePairRateTx
	DepositTx          = types.DepositTx
	DepositNftTx       = types.DepositNftTx
	TransferTx         = types.TransferTx
	SwapTx             = types.SwapTx
	AddLiquidityTx     = types.AddLiquidityTx
	RemoveLiquidityTx  = types.RemoveLiquidityTx
	CreateCollectionTx = types.CreateCollectionTx
	MintNftTx          = types.MintNftTx
	TransferNftTx      = types.TransferNftTx
	AtomicMatchTx      = types.AtomicMatchTx
	CancelOfferTx      = types.CancelOfferTx
	WithdrawTx         = types.WithdrawTx
	WithdrawNftTx      = types.WithdrawNftTx
	FullExitTx         = types.FullExitTx
	FullExitNftTx      = types.FullExitNftTx

	RegisterZnsTxConstraints      = types.RegisterZnsTxConstraints
	CreatePairTxConstraints       = types.CreatePairTxConstraints
	UpdatePairRateTxConstraints   = types.UpdatePairRateTxConstraints
	DepositTxConstraints          = types.DepositTxConstraints
	DepositNftTxConstraints       = types.DepositNftTxConstraints
	TransferTxConstraints         = types.TransferTxConstraints
	SwapTxConstraints             = types.SwapTxConstraints
	AddLiquidityTxConstraints     = types.AddLiquidityTxConstraints
	RemoveLiquidityTxConstraints  = types.RemoveLiquidityTxConstraints
	CreateCollectionTxConstraints = types.CreateCollectionTxConstraints
	MintNftTxConstraints          = types.MintNftTxConstraints
	TransferNftTxConstraints      = types.TransferNftTxConstraints
	AtomicMatchTxConstraints      = types.AtomicMatchTxConstraints
	CancelOfferTxConstraints      = types.CancelOfferTxConstraints
	WithdrawTxConstraints         = types.WithdrawTxConstraints
	WithdrawNftTxConstraints      = types.WithdrawNftTxConstraints
	FullExitTxConstraints         = types.FullExitTxConstraints
	FullExitNftTxConstraints      = types.FullExitNftTxConstraints

	LiquidityConstraints = types.LiquidityConstraints
	NftConstraints       = types.NftConstraints
)

const (
	NbAccountAssetsPerAccount = types.NbAccountAssetsPerAccount
	NbAccountsPerTx           = types.NbAccountsPerTx
	AssetMerkleLevels         = 16
	LiquidityMerkleLevels     = 16
	NftMerkleLevels           = 40
	AccountMerkleLevels       = 32
	RateBase                  = types.RateBase
	OfferSizePerAsset         = 128

	LastAccountIndex   = 4294967295
	LastAccountAssetId = 65535

	LastPairIndex = 65535
	LastNftIndex  = 1099511627775
)
