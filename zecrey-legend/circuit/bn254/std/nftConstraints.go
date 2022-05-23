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
	"errors"
	"log"
)

type NftConstraints struct {
	NftIndex            Variable
	NftContentHash      Variable
	CreatorAccountIndex Variable
	OwnerAccountIndex   Variable
	NftL1Address        Variable
	NftL1TokenId        Variable
	CreatorTreasuryRate Variable
	CollectionId        Variable
}

func CheckEmptyNftNode(api API, flag Variable, nft NftConstraints) {
	IsVariableEqual(api, flag, nft.NftContentHash, ZeroInt)
	IsVariableEqual(api, flag, nft.CreatorAccountIndex, ZeroInt)
	IsVariableEqual(api, flag, nft.OwnerAccountIndex, ZeroInt)
	IsVariableEqual(api, flag, nft.NftL1Address, ZeroInt)
	IsVariableEqual(api, flag, nft.NftL1TokenId, ZeroInt)
	IsVariableEqual(api, flag, nft.CreatorTreasuryRate, ZeroInt)
	IsVariableEqual(api, flag, nft.CollectionId, ZeroInt)
}

/*
	SetNftWitness: set liquidity witness
*/
func SetNftWitness(nft *Nft) (witness NftConstraints, err error) {
	if nft == nil {
		log.Println("[SetNftWitness] invalid params")
		return witness, errors.New("[SetNftWitness] invalid params")
	}
	// set witness
	witness = NftConstraints{
		NftIndex:            nft.NftIndex,
		NftContentHash:      nft.NftContentHash,
		CreatorAccountIndex: nft.CreatorAccountIndex,
		OwnerAccountIndex:   nft.OwnerAccountIndex,
		NftL1Address:        nft.NftL1Address,
		NftL1TokenId:        nft.NftL1TokenId,
		CreatorTreasuryRate: nft.CreatorTreasuryRate,
		CollectionId:        nft.CollectionId,
	}
	return witness, nil
}
