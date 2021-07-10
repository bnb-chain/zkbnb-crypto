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

package zecrey

import (
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/bulletProofs"
	"zecrey-crypto/rangeProofs/twistededwards/tebn254/commitRange"
)

type (
	ElGamalEnc     = twistedElgamal.ElGamalEnc
	Point          = curve.Point
	BPSetupParams  = bulletProofs.BPSetupParams
	AggBulletProof = bulletProofs.AggBulletProof
)

const (
	RangeMaxBits      = commitRange.RangeMaxBits // max bits
	PointSize         = curve.PointSize
	RangeProofSize    = commitRange.RangeProofSize
	WithdrawProofSize = 21*PointSize + RangeProofSize + 2*8
)

var (
	G         = curve.G
	H         = curve.H
	Order     = curve.Order
	Zero      = big.NewInt(0)
	PadSecret = big.NewInt(0)
)
