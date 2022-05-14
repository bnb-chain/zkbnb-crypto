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
	A, B, C, D Variable
	E, F, G, H Variable
}

const (
	PackedAmountMaxMantissa = int64(34359738367)
)

func UnpackAmount(api API, packedAmount Variable) Variable {
	amountBits := api.ToBinary(packedAmount, 40)
	mantissa := api.FromBinary(amountBits[5:]...)
	exponent := api.FromBinary(amountBits[:5]...)
	for i := 0; i < 32; i++ {
		isRemain := api.Cmp(exponent, 0)
		mantissa = api.Select(isRemain, api.Mul(mantissa, 10), mantissa)
		exponent = api.Select(isRemain, api.Sub(exponent, 1), exponent)
	}
	return mantissa
}

// define for range proof test
func (circuit ByteConstraints) Define(api API) error {
	// mimc
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	ABits := api.ToBinary(circuit.A, 128)
	BBits := api.ToBinary(circuit.B, 160)
	CBits := api.ToBinary(circuit.C, 240)
	ABBits := append(BBits[32:], ABits...)
	BCBits := append(CBits[16:], BBits[:32]...)
	CCBits := CBits[:16]
	AB1 := api.FromBinary(ABBits...)
	AB2 := api.FromBinary(BCBits...)
	AB3 := api.FromBinary(CCBits...)
	api.Println(AB1)
	api.Println(AB2)
	api.Println(AB3)
	hFunc.Write(AB1)
	hFunc.Write(AB2)
	hFunc.Write(AB3)
	var bytes []Variable
	bytes = append(bytes, AB1)
	//bytes = append(bytes, nil)
	//for _, info := range bytes {
	//	api.Println(info)
	//}
	a := 2
	flag := api.Compiler().IsBoolean(a)
	if flag {
		hFunc.Write(1)
	}
	//hFunc.Write([]byte{})
	ABHash := hFunc.Sum()
	api.AssertIsEqual(ABHash, circuit.D)
	hFunc.Reset()
	EBits := api.ToBinary(circuit.E, 8)
	FBits := api.ToBinary(circuit.F, 8)
	GBits := api.ToBinary(circuit.G, 8)
	bits := append(FBits, EBits...)
	bits = append(GBits, bits...)
	H := api.FromBinary(bits...)
	hFunc.Write(H)
	hHash := hFunc.Sum()
	api.AssertIsEqual(hHash, circuit.H)

	packedAmount := UnpackAmount(api, 355555555554)
	api.Println(packedAmount)
	return nil
}
