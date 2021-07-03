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
)

type (
	Point                 = twistededwards.Point
	Variable              = frontend.Variable
	ConstraintSystem      = frontend.ConstraintSystem
	ElGamalEncConstraints = std.ElGamalEncConstraints
	MiMC                  = mimc.MiMC
)

const (
	NbTxs               = 2
	AccountMerkleLevels = std.AccountMerkleLevels
	NbTransferCount     = std.NbTransferCount
	NbSwapCount         = 2
	BalanceMerkleLevels = 16

	// size
	PointSize   = curve.PointSize
	EncSize     = twistedElgamal.EncSize
	AccountSize = 160

	DepositTxType  = 1
	TransferTxType = 2
	SwapTxType     = 3
	WithdrawTxType = 4
)
