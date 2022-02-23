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
	"github.com/zecrey-labs/zecrey-crypto/accumulators/merkleTree"
	curve "github.com/zecrey-labs/zecrey-crypto/ecc/ztwistededwards/tebn254"
	"github.com/zecrey-labs/zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"github.com/zecrey-labs/zecrey-crypto/zecrey/circuit/bn254/std"
	"github.com/zecrey-labs/zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
	"math/big"
)

type (
	EccTool = std.EccTool

	Point                 = twistededwards.Point
	Variable              = frontend.Variable
	API                   = frontend.API
	ElGamalEncConstraints = std.ElGamalEncConstraints
	MiMC                  = mimc.MiMC

	DepositOrLockTx      = std.DepositOrLockTx
	UnlockProof          = zecrey.UnlockProof
	TransferProof        = zecrey.TransferProof
	TransferSubProof     = zecrey.TransferSubProof
	SwapProof            = zecrey.SwapProof
	AddLiquidityProof    = zecrey.AddLiquidityProof
	RemoveLiquidityProof = zecrey.RemoveLiquidityProof
	WithdrawProof        = zecrey.WithdrawProof

	CtRangeProofConstraints         = std.CtRangeProofConstraints
	DepositOrLockTxConstraints      = std.DepositOrLockTxConstraints
	UnlockProofConstraints          = std.UnlockProofConstraints
	TransferProofConstraints        = std.TransferProofConstraints
	TransferSubProofConstraints     = std.TransferSubProofConstraints
	SwapProofConstraints            = std.SwapProofConstraints
	AddLiquidityProofConstraints    = std.AddLiquidityProofConstraints
	RemoveLiquidityProofConstraints = std.RemoveLiquidityProofConstraints
	WithdrawProofConstraints        = std.WithdrawProofConstraints
)

const (
	MaxRangeProofCount        = 3
	TxsCountForTest           = 1
	NbTxsCountHalf            = 70
	NbTxsCountFull            = 140
	NbAccountsPerTx           = 4
	NbAccountAssetsPerAccount = 3
	AccountMerkleLevels       = 33
	AccountMerkleHelperLevels = AccountMerkleLevels - 1
	AssetMerkleLevels         = 17
	AssetMerkleHelperLevels   = AssetMerkleLevels - 1

	LockedAssetMerkleLevels       = 17
	LockedAssetMerkleHelperLevels = LockedAssetMerkleLevels - 1
	LiquidityMerkleLevels         = 17
	LiquidityMerkleHelperLevels   = LiquidityMerkleLevels - 1
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
)

var (
	NilHash     = merkleTree.NilHash
	NilHashFull = new(big.Int).SetBytes(NilHash).FillBytes(make([]byte, PointSize))
)
