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
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/zecrey/circuit/bn254/std"
	"zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
)

type (
	Point                 = twistededwards.Point
	Variable              = frontend.Variable
	API                   = frontend.API
	ElGamalEncConstraints = std.ElGamalEncConstraints
	MiMC                  = mimc.MiMC

	TransferProof        = zecrey.TransferProof
	SwapProof            = zecrey.SwapProof
	AddLiquidityProof    = zecrey.AddLiquidityProof
	RemoveLiquidityProof = zecrey.RemoveLiquidityProof
	WithdrawProof        = zecrey.WithdrawProof

	CtRangeProofConstraints         = std.CtRangeProofConstraints
	TransferProofConstraints        = std.TransferProofConstraints
	SwapProofConstraints            = std.SwapProofConstraints
	AddLiquidityProofConstraints    = std.AddLiquidityProofConstraints
	RemoveLiquidityProofConstraints = std.RemoveLiquidityProofConstraints
	WithdrawProofConstraints        = std.WithdrawProofConstraints
)

const (
	MaxRangeProofCount    = 3
	NbTxs                 = 20
	AccountMerkleLevels   = std.AccountMerkleLevels
	NbTransferCount       = std.NbTransferCount
	NbTransferCountAndFee = NbTransferCount + 1
	NbSwapCount           = 2
	NbSwapCountAndFee     = NbSwapCount + 1
	NbWithdrawCountAndFee = 2
	BalanceMerkleLevels   = 16

	// size
	PointSize   = curve.PointSize
	EncSize     = twistedElgamal.EncSize
	AccountSize = 160

	TxTypeNoop            = 1
	TxTypeDeposit         = 2
	TxTypeLock            = 3
	TxTypeTransfer        = 4
	TxTypeSwap            = 5
	TxTypeAddLiquidity    = 6
	TxTypeRemoveLiquidity = 7
	TxTypeUnlock          = 8
	TxTypeWithdraw        = 9
)
