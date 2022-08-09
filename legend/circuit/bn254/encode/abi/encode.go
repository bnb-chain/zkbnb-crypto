// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package abi

import (
	"github.com/consensys/gnark/frontend"
)

type Circuit struct {
	AbiId  frontend.Variable
	Values []frontend.Variable // variable name
	Bytes  []frontend.Variable `gnark:",public"` // abi object
	Name   frontend.Variable   `gnark:",public"` // abi object
}

func (circuit *Circuit) Define(api frontend.API) error {
	encoder, err := NewAbiEncoder(api, circuit.AbiId)
	if err != nil {
		return err
	}

	res, err := encoder.Pack(api, circuit.Name, circuit.Values...)
	if err != nil {
		return err
	}

	for i := range res {
		validRes := api.Select(api.IsZero(api.Sub(res[i], 256)), 0, res[i])
		api.AssertIsEqual(validRes, circuit.Bytes[i])
	}
	return nil
}
