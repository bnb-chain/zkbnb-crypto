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

package types

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	eddsaConstraints "github.com/consensys/gnark/std/signature/eddsa"
)

func SetPubKeyWitness(pk *eddsa.PublicKey) (witness eddsaConstraints.PublicKey) {
	witness.A.X = pk.A.X
	witness.A.Y = pk.A.Y
	return witness
}

func EmptyPublicKeyWitness() (witness PublicKeyConstraints) {
	witness = PublicKeyConstraints{
		A: twistededwards.Point{
			X: ZeroInt,
			Y: ZeroInt,
		},
	}
	return witness
}

func Max(api API, a, b Variable) Variable {
	maxAB := api.Select(api.IsZero(api.Sub(1, api.Cmp(a, b))), a, b)
	return maxAB
}

func Min(api API, a, b Variable) Variable {
	minAB := api.Select(api.IsZero(api.Add(1, api.Cmp(a, b))), a, b)
	return minAB
}

func CopyLittleEndianSlice(target []Variable, src []Variable) {
	for i, j := len(target)-1, 0; i >= 0; i, j = i-1, j+1 {
		target[i] = src[j]
	}
}

func copyLittleEndianSliceAndShiftOffset(api API, txField Variable, txFiledBitsSize int, currentOffset *int, pubData []Variable) {
	txFiledBits := api.ToBinary(txField, txFiledBitsSize)
	CopyLittleEndianSlice(pubData[*currentOffset:*currentOffset+txFiledBitsSize], txFiledBits)
	*currentOffset += txFiledBitsSize
}
