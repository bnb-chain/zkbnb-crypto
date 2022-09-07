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

package block

import (
	"github.com/bnb-chain/zkbas-crypto/legend/circuit/bn254/std"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	eddsaConstraints "github.com/consensys/gnark/std/signature/eddsa"
)

type (
	Variable = frontend.Variable

	Signature            = eddsa.Signature
	SignatureConstraints = eddsaConstraints.Signature
	API                  = frontend.API
	MiMC                 = mimc.MiMC

	RegisterZnsTx      = std.RegisterZnsTx
	CreatePairTx       = std.CreatePairTx
	UpdatePairRateTx   = std.UpdatePairRateTx
	DepositTx          = std.DepositTx
	DepositNftTx       = std.DepositNftTx
	TransferTx         = std.TransferTx
	SwapTx             = std.SwapTx
	AddLiquidityTx     = std.AddLiquidityTx
	RemoveLiquidityTx  = std.RemoveLiquidityTx
	CreateCollectionTx = std.CreateCollectionTx
	MintNftTx          = std.MintNftTx
	TransferNftTx      = std.TransferNftTx
	AtomicMatchTx      = std.AtomicMatchTx
	CancelOfferTx      = std.CancelOfferTx
	WithdrawTx         = std.WithdrawTx
	WithdrawNftTx      = std.WithdrawNftTx
	FullExitTx         = std.FullExitTx
	FullExitNftTx      = std.FullExitNftTx

	RegisterZnsTxConstraints      = std.RegisterZnsTxConstraints
	CreatePairTxConstraints       = std.CreatePairTxConstraints
	UpdatePairRateTxConstraints   = std.UpdatePairRateTxConstraints
	DepositTxConstraints          = std.DepositTxConstraints
	DepositNftTxConstraints       = std.DepositNftTxConstraints
	TransferTxConstraints         = std.TransferTxConstraints
	SwapTxConstraints             = std.SwapTxConstraints
	AddLiquidityTxConstraints     = std.AddLiquidityTxConstraints
	RemoveLiquidityTxConstraints  = std.RemoveLiquidityTxConstraints
	CreateCollectionTxConstraints = std.CreateCollectionTxConstraints
	MintNftTxConstraints          = std.MintNftTxConstraints
	TransferNftTxConstraints      = std.TransferNftTxConstraints
	AtomicMatchTxConstraints      = std.AtomicMatchTxConstraints
	CancelOfferTxConstraints      = std.CancelOfferTxConstraints
	WithdrawTxConstraints         = std.WithdrawTxConstraints
	WithdrawNftTxConstraints      = std.WithdrawNftTxConstraints
	FullExitTxConstraints         = std.FullExitTxConstraints
	FullExitNftTxConstraints      = std.FullExitNftTxConstraints

	LiquidityConstraints = std.LiquidityConstraints
	NftConstraints       = std.NftConstraints
	ValuesConstraints    = std.ValuesConstraints
)

const (
	NbAccountAssetsPerAccount = std.NbAccountAssetsPerAccount
	NbAccountsPerTx           = std.NbAccountsPerTx
	AssetMerkleLevels         = 16
	LiquidityMerkleLevels     = 16
	NftMerkleLevels           = 40
	AccountMerkleLevels       = 32
	RateBase                  = std.RateBase
	OfferSizePerAsset         = 128

	LastAccountIndex   = 4294967295
	LastAccountAssetId = 65535
)
