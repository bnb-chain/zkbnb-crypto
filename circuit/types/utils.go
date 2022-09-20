/*
 * Copyright © 2022 ZkBNB Protocol
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

package types

import (
	"errors"
	"github.com/bnb-chain/zkbnb-crypto/ffmath"
	"github.com/bnb-chain/zkbnb-crypto/util"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	eddsaConstraints "github.com/consensys/gnark/std/signature/eddsa"
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

func Max(api API, a, b Variable) Variable {
	maxAB := api.Select(api.IsZero(api.Sub(1, api.Cmp(a, b))), a, b)
	return maxAB
}

func Min(api API, a, b Variable) Variable {
	minAB := api.Select(api.IsZero(api.Add(1, api.Cmp(a, b))), a, b)
	return minAB
}


func ComputeSLp(curveID ecc.ID, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 5 {
		return errors.New("[ComputeSLp] invalid params")
	}
	poolA := inputs[0]
	poolB := inputs[1]
	kLast := inputs[2]
	feeRate := inputs[3]
	treasuryRate := inputs[4]
	if poolA.Cmp(util.ZeroBigInt) == 0 || poolB.Cmp(util.ZeroBigInt) == 0 {
		outputs[0] = util.ZeroBigInt
		return nil
	}
	kCurrent := ffmath.Multiply(poolA, poolB)
	kLast.Sqrt(kLast)
	kCurrent.Sqrt(kCurrent)
	l := ffmath.Multiply(ffmath.Sub(kCurrent, kLast), big.NewInt(RateBase))
	r := ffmath.Multiply(ffmath.Sub(ffmath.Multiply(big.NewInt(RateBase), ffmath.Div(feeRate, treasuryRate)), big.NewInt(RateBase)), kCurrent)
	r = ffmath.Add(r, ffmath.Multiply(big.NewInt(RateBase), kLast))
	var err error
	outputs[0], err = util.CleanPackedAmount(ffmath.Div(l, r))
	if err != nil {
		return err
	}
	return nil
}

