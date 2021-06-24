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

package linear

import (
	"bytes"
	"math/big"
	curve "zecrey-crypto/ecc/ztwistededwards/tebn254"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/util"
)

func HashLinear(UtArr, uArr []*Point) *big.Int {
	UtBytes, _ := curve.VecToBytes(UtArr)
	uBytes, _ := curve.VecToBytes(uArr)
	var buffer bytes.Buffer
	buffer.Write(UtBytes)
	buffer.Write(uBytes)
	c, _ := util.HashToInt(buffer, zmimc.Hmimc)
	return c
}
