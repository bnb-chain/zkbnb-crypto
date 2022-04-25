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

func IsEmptyNftInfo(api API, flag Variable, zeroHash Variable, nftInfo AccountNftConstraints) {
	IsVariableEqual(api, flag, nftInfo.NftAssetId, DefaultInt)
	IsVariableEqual(api, flag, nftInfo.NftIndex, DefaultInt)
	IsVariableEqual(api, flag, nftInfo.NftContentHash, zeroHash)
	IsVariableEqual(api, flag, nftInfo.AssetId, DefaultInt)
	IsVariableEqual(api, flag, nftInfo.AssetAmount, 0)
	IsVariableEqual(api, flag, nftInfo.NftL1TokenId, DefaultInt)
	IsVariableEqual(api, flag, nftInfo.NftL1Address, zeroHash)
}
