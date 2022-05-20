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
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	eddsaConstraints "github.com/consensys/gnark/std/signature/eddsa"
	"github.com/zecrey-labs/zecrey-crypto/ffmath"
	"math/big"
)

func SetPubKeyWitness(pk *eddsa.PublicKey) (witness eddsaConstraints.PublicKey) {
	witness.A.X = pk.A.X
	witness.A.Y = pk.A.Y
	return witness
}

func EmptyPublicKeyWitness() (witness PublicKeyConstraints) {
	witness = PublicKeyConstraints{
		A: twistededwards.Point{
			X: ZeroInt,
			Y: ZeroInt,
		},
	}
	return witness
}

func ComputeSLp(api API, flag Variable, poolA, poolB Variable, kLastVar Variable, feeRateVar, treasuryRateVar Variable) Variable {
	kCurrentVar := api.Mul(poolA, poolB)
	IsVariableLessOrEqual(api, flag, kLastVar, kCurrentVar)
	IsVariableLessOrEqual(api, flag, treasuryRateVar, feeRateVar)
	isZeroVar := api.IsZero(kCurrentVar)
	isZero := api.Compiler().IsBoolean(isZeroVar)
	if isZero {
		return 0
	}
	kLast, _ := api.Compiler().ConstantValue(kLastVar)
	if kLast == nil {
		kLast = big.NewInt(0)
	}
	kCurrent, _ := api.Compiler().ConstantValue(kCurrentVar)
	if kCurrent == nil {
		kCurrent = big.NewInt(0)
	}
	kLast.Sqrt(kLast)
	kCurrent.Sqrt(kCurrent)
	l := ffmath.Multiply(ffmath.Sub(kCurrent, kLast), big.NewInt(RateBase))
	feeRate, _ := api.Compiler().ConstantValue(feeRateVar)
	treasuryRate, _ := api.Compiler().ConstantValue(treasuryRateVar)
	r := ffmath.Multiply(ffmath.Sub(ffmath.Multiply(big.NewInt(RateBase), ffmath.Div(feeRate, treasuryRate)), big.NewInt(RateBase)), kCurrent)
	r = ffmath.Add(r, ffmath.Multiply(big.NewInt(RateBase), kLast))
	return ffmath.Div(l, r)
}
