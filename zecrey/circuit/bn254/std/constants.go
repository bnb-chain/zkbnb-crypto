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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/commitRange"
)

type (
	Point            = twistededwards.Point
	Variable         = frontend.Variable
	ConstraintSystem = frontend.ConstraintSystem
	MiMC             = mimc.MiMC
	ElgamalEnc       = twistedElgamal.ElGamalEnc
)

const (
	// TODO only for test
	AccountMerkleLevels = 18
	NbTransferCount     = 3
	RangeMaxBits        = commitRange.RangeMaxBits
)

var (
	HX, _          = new(big.Int).SetString("19843132008705182383524593512377323181208938069977784352990768375941636129043", 10)
	HY, _          = new(big.Int).SetString("1424962496956403694866513262744390851176749772810717397211030275710635902220", 10)
	BasePoint      = curve.G
	ZeroInt        = uint64(0)
	ZeroElgamalEnc = &ElgamalEnc{CL: BasePoint, CR: BasePoint}
)
