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

package util

import (
	"bytes"
	"hash"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func HashToInt(b bytes.Buffer, h hash.Hash) (*big.Int, error) {
	h = mimc.NewMiMC()
	digest := h
	digest.Write(b.Bytes())
	output := digest.Sum(nil)
	//tmp := output[0:]
	//return FromByteArray(tmp)
	return new(big.Int).SetBytes(output), nil
}
