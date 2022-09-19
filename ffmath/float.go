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

package ffmath

import (
	"math/big"
)

func FloatAdd(a, b *big.Float) *big.Float {
	return new(big.Float).Add(a, b)
}

func FloatSub(a, b *big.Float) *big.Float {
	return new(big.Float).Sub(a, b)
}

func FloatDiv(a, b *big.Float) *big.Float {
	return new(big.Float).Quo(a, b)
}

func FloatDivByInt(a, b *big.Int) *big.Float {
	aFloat := IntToFloat(a)
	bFloat := IntToFloat(b)
	return FloatDiv(aFloat, bFloat)
}

func FloatMul(a, b *big.Float) *big.Float {
	return new(big.Float).Mul(a, b)
}

func FloatSqrt(a *big.Float) *big.Float {
	return new(big.Float).Sqrt(a)
}

func IntToFloat(a *big.Int) *big.Float {
	return new(big.Float).SetInt(a)
}

func FloatToInt(a *big.Float) *big.Int {
	res, _ := a.Int(nil)
	return res
}
