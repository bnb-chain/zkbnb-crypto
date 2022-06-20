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

package pedersen

import (
	"math/big"
	"github.com/bnb-chain/zkbas-crypto/ecc/zp256"
)

type P256 = zp256.P256

func Commit(a *big.Int, r *big.Int, g, h *P256) *P256 {
	commitment := zp256.ScalarMul(g, a)
	commitment.Add(commitment, zp256.ScalarMul(h, r))
	return commitment
}
