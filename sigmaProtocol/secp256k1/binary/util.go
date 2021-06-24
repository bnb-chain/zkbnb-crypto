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

package binary

import (
	"bytes"
	"math/big"
	"zecrey-crypto/hash/bn254/zmimc"
	"zecrey-crypto/util"
)

func HashChallenge(ca, cb *P256) *big.Int {
	toBytes := util.ContactBytes(ca.Bytes(),
		cb.Bytes())
	var buffer bytes.Buffer
	buffer.Write(toBytes)
	c, _ := util.HashToInt(buffer, zmimc.Hmimc)
	return c
}
