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

package transactions

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/bnb-chain/zkbas-crypto/accumulators/merkleTree"
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"github.com/bnb-chain/zkbas-crypto/zero/circuit/bn254/std"
	"github.com/bnb-chain/zkbas-crypto/zero/twistededwards/tebn254/zero"
)

type (
	EccTool = std.EccTool

	Point                 = twistededwards.Point
	Variable              = frontend.Variable
	API                   = frontend.API
	ElGamalEncConstraints = std.ElGamalEncConstraints
	MiMC                  = mimc.MiMC

	DepositOrLockTx      = std.DepositOrLockTx
	DepositNftTx         = std.DepositNftTx
	UnlockProof          = zero.UnlockProof
	TransferProof        = zero.TransferProof
	TransferSubProof     = zero.TransferSubProof
	SwapProof            = zero.SwapProof
	AddLiquidityProof    = zero.AddLiquidityProof
	RemoveLiquidityProof = zero.RemoveLiquidityProof
	WithdrawProof        = zero.WithdrawProof
	MintNftProof         = zero.MintNftProof
	TransferNftProof     = zero.TransferNftProof
	SetNftPriceProof     = zero.SetNftPriceProof
	BuyNftProof          = zero.BuyNftProof
	WithdrawNftProof     = zero.WithdrawNftProof

	CtRangeProofConstraints         = std.CtRangeProofConstraints
	DepositOrLockTxConstraints      = std.DepositOrLockTxConstraints
	UnlockProofConstraints          = std.UnlockProofConstraints
	TransferProofConstraints        = std.TransferProofConstraints
	TransferSubProofConstraints     = std.TransferSubProofConstraints
	SwapProofConstraints            = std.SwapProofConstraints
	AddLiquidityProofConstraints    = std.AddLiquidityProofConstraints
	RemoveLiquidityProofConstraints = std.RemoveLiquidityProofConstraints
	WithdrawProofConstraints        = std.WithdrawProofConstraints
	DepositNftTxConstraints         = std.DepositNftTxConstraints
	MintNftProofConstraints         = std.MintNftProofConstraints
	TransferNftProofConstraints     = std.TransferNftProofConstraints
	SetNftPriceProofConstraints     = std.SetNftPriceProofConstraints
	BuyNftProofConstraints          = std.BuyNftProofConstraints
	WithdrawNftProofConstraints     = std.WithdrawNftProofConstraints
)

const (
	MaxRangeProofCount        = 3
	TxsCountPerBlock          = 3
	NbTxsCountHalf            = 70
	NbTxsCountFull            = 140
	NbAccountsPerTx           = std.NbAccountsPerTx
	NbAccountAssetsPerAccount = std.NbAccountAssetsPerAccount
	AccountMerkleLevels       = 33
	AccountMerkleHelperLevels = AccountMerkleLevels - 1
	AssetMerkleLevels         = 17
	AssetMerkleHelperLevels   = AssetMerkleLevels - 1

	LockedAssetMerkleLevels       = 17
	LockedAssetMerkleHelperLevels = LockedAssetMerkleLevels - 1
	LiquidityMerkleLevels         = 17
	LiquidityMerkleHelperLevels   = LiquidityMerkleLevels - 1
	NftMerkleLevels               = 33
	NftMerkleHelperLevels         = NftMerkleLevels - 1
	NbTransferCount               = std.NbTransferCount
	NbTransferCountAndFee         = NbTransferCount + 1
	NbSwapCount                   = 2
	NbSwapCountAndFee             = NbSwapCount + 1
	NbWithdrawCountAndFee         = 2
	BalanceMerkleLevels           = 16

	// size
	PointSize   = curve.PointSize
	EncSize     = twistedElgamal.EncSize
	AccountSize = 160

	TxTypeNoop            = 0
	TxTypeDeposit         = 1
	TxTypeLock            = 2
	TxTypeUnlock          = 3
	TxTypeTransfer        = 4
	TxTypeSwap            = 5
	TxTypeAddLiquidity    = 6
	TxTypeRemoveLiquidity = 7
	TxTypeWithdraw        = 8
	TxTypeDepositNft      = 9
	TxTypeMintNft         = 10
	TxTypeTransferNft     = 11
	TxTypeSetNftPrice     = 12
	TxTypeBuyNft          = 13
	TxTypeWithdrawNft     = 14

	// deposit or lock
	DepositFromAccount          = 0
	DepositFromAccountFromAsset = 0
	LockFromAccount             = 0
	// unlock related account index
	UnlockFromAccount            = 0
	UnlockFromAccountUnlockAsset = 0
	UnlockFromAccountGasAsset    = 1
	UnlockGasAccount             = 1
	UnlockGasAccountGasAsset     = 0
	// transfer related account index
	TransferAccountTransferAsset = 0
	TransferAccountA             = 0
	TransferAccountB             = 1
	TransferAccountC             = 2
	TransferGasAccount           = 3
	// swap related account index
	SwapFromAccount         = 0
	SwapFromAccountAssetA   = 0
	SwapFromAccountAssetB   = 1
	SwapFromAccountGasAsset = 2
	SwapPoolAccount         = 1
	SwapTreasuryAccount     = 2
	SwapGasAccount          = 3
	// add liquidity related account index
	AddLiquidityFromAccount         = 0
	AddLiquidityFromAccountAssetA   = 0
	AddLiquidityFromAccountAssetB   = 1
	AddLiquidityFromAccountGasAsset = 2
	AddLiquidityPoolAccount         = 1
	AddLiquidityGasAccount          = 2
	// remove liquidity related account index
	RemoveLiquidityFromAccount         = 0
	RemoveLiquidityFromAccountAssetA   = 0
	RemoveLiquidityFromAccountAssetB   = 1
	RemoveLiquidityFromAccountGasAsset = 2
	RemoveLiquidityPoolAccount         = 1
	RemoveLiquidityGasAccount          = 2
	// withdraw related account index
	WithdrawFromAccount         = 0
	WithdrawFromAccountAsset    = 0
	WithdrawFromAccountGasAsset = 1
	WithdrawGasAccount          = 1
	// deposit nft related account index
	// mint nft related account index
	MintNftFromAccount         = 0
	MintNftFromAccountGasAsset = 0
	MintNftGasAccount          = 1
	MintNftToAccount           = 2
	// transfer nft related account index
	TransferNftFromAccount         = 0
	TransferNftFromAccountGasAsset = 0
	TransferNftGasAccount          = 1
	// set nft price related account index
	SetNftPriceFromAccount         = 0
	SetNftPriceFromAccountGasAsset = 0
	SetNftPriceGasAccount          = 1
	// buy nft related account index
	BuyNftFromAccount         = 0
	BuyNftFromAccountAsset    = 0
	BuyNftFromAccountGasAsset = 1
	BuyNftGasAccount          = 1
	BuyNftToAccount           = 2
	// withdraw nft related account index
	WithdrawNftFromAccount         = 0
	WithdrawNftFromAccountGasAsset = 0
	WithdrawNftGasAccount          = 1
)

var (
	NilHash = merkleTree.NilHash
)
