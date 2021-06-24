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
)

type (
	ElGamalEnc     = twistedElgamal.ElGamalEnc
	Point          = curve.Point
	BPSetupParams  = bulletProofs.BPSetupParams
	AggBulletProof = bulletProofs.AggBulletProof
)

const (
	N   = 32 // max bits
	Max = 4294967296
)

var (
	G            = curve.G
	H            = curve.H
	Order        = curve.Order
	Zero         = big.NewInt(0)
	PadSecret    = big.NewInt(0)
	PadGammas, _ = new(big.Int).SetString("2029490050459469381010394860546295858668907545094365921480173886327233296650", 10)
	PadV         = curve.ScalarMul(G, PadGammas)
)
