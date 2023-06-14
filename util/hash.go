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
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func HashToInt(b bytes.Buffer) (*big.Int, error) {
	if b.Len() == 0 {
		return nil, errors.New("input is empty")
	}
	digest := mimc.NewMiMC()
	var x fr.Element
	_ = x.SetBytes(b.Bytes())
	bs := x.Bytes()
	_, err := digest.Write(bs[:])
	if err != nil {
		return nil, err
	}
	output := digest.Sum(nil)
	//tmp := output[0:]
	//return FromByteArray(tmp)
	return new(big.Int).SetBytes(output), nil
}
