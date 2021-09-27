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

package ctrange

import (
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
)

const (
	RangeMaxBits   = 32
	RangeProofSize = RangeMaxBits*2*PointSize + 4*PointSize
	PointSize      = 32
	ErrCode        = -1
)

var (
	Order = curve.Order
	Q, _  = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
)

type Point = curve.Point
