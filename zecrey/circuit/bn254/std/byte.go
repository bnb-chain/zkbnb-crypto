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
	"github.com/consensys/gnark/std/hash/mimc"
)

type ByteConstraints struct {
	A, B, C Variable
}

// define for range proof test
func (circuit ByteConstraints) Define(api API) error {
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	api.Println(circuit.A)
	ABits := api.ToBinary(circuit.A, 256)
	BBits := api.ToBinary(circuit.B, 128)
	ABBits := append(ABits, BBits[:90]...)
	api.Println(ABits...)
	AB1 := api.FromBinary(ABBits...)
	AB2 := api.FromBinary(BBits[90:]...)
	hFunc.Write(AB1)
	hFunc.Write(AB2)
	ABHash := hFunc.Sum()
	api.AssertIsEqual(ABHash, circuit.C)
	return nil
}
