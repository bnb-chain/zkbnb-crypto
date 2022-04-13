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
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	eddsaConstraints "github.com/consensys/gnark/std/signature/eddsa"
	"github.com/zecrey-labs/zecrey-crypto/accumulators/merkleTree"
	"github.com/zecrey-labs/zecrey-crypto/zecrey-legend/circuit/bn254/std"
)

type (
	Variable = frontend.Variable

	Signature            = eddsa.Signature
	SignatureConstraints = eddsaConstraints.Signature
	API                  = frontend.API
	MiMC                 = mimc.MiMC

	RegisterZnsTx     = std.RegisterZnsTx
	DepositTx         = std.DepositTx
	DepositNftTx      = std.DepositNftTx
	GenericTransferTx = std.GenericTransferTx
	SwapTx            = std.SwapTx
	AddLiquidityTx    = std.AddLiquidityTx
	RemoveLiquidityTx = std.RemoveLiquidityTx
	MintNftTx         = std.MintNftTx
	SetNftPriceTx     = std.SetNftPriceTx
	BuyNftTx          = std.BuyNftTx
	WithdrawTx        = std.WithdrawTx
	WithdrawNftTx     = std.WithdrawNftTx

	RegisterZnsTxConstraints     = std.RegisterZnsTxConstraints
	DepositTxConstraints         = std.DepositTxConstraints
	DepositNftTxConstraints      = std.DepositNftTxConstraints
	GenericTransferTxConstraints = std.GenericTransferTxConstraints
	SwapTxConstraints            = std.SwapTxConstraints
	AddLiquidityTxConstraints    = std.AddLiquidityTxConstraints
	RemoveLiquidityTxConstraints = std.RemoveLiquidityTxConstraints
	MintNftTxConstraints         = std.MintNftTxConstraints
	SetNftPriceTxConstraints     = std.SetNftPriceTxConstraints
	BuyNftTxConstraints          = std.BuyNftTxConstraints
	WithdrawTxConstraints        = std.WithdrawTxConstraints
	WithdrawNftTxConstraints     = std.WithdrawNftTxConstraints
)

const (
	TxTypeEmptyTx = iota
	TxTypeRegisterZns
	TxTypeDeposit
	TxTypeDepositNft
	TxTypeGenericTransfer
	TxTypeSwap
	TxTypeAddLiquidity
	TxTypeRemoveLiquidity
	TxTypeWithdraw
	TxTypeMintNft
	TxTypeSetNftPrice
	TxTypeBuyNft
	TxTypeWithdrawNft
)

const (
	NbAccountAssetsPerAccount = 4
	NbAccountsPerTx           = 4
	AssetMerkleLevels         = 17
	AssetMerkleHelperLevels   = AssetMerkleLevels - 1
	NftMerkleLevels           = 33
	NftMerkleHelperLevels     = NftMerkleLevels - 1
	AccountMerkleLevels       = 33
	AccountMerkleHelperLevels = AccountMerkleLevels - 1
)

var (
	NilHash = merkleTree.NilHash
)
