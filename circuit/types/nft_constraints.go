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
	"errors"
	"log"
)

type NftConstraints struct {
	NftIndex            Variable
	NftContentHash      [2]Variable
	CreatorAccountIndex Variable
	OwnerAccountIndex   Variable
	RoyaltyRate         Variable
	CollectionId        Variable
	NftContentType      Variable
}

func CheckEmptyNftNode(api API, flag Variable, nft NftConstraints) {
	IsVariableEqual(api, flag, nft.NftContentHash[0], ZeroInt)
	IsVariableEqual(api, flag, nft.NftContentHash[1], ZeroInt)
	IsVariableEqual(api, flag, nft.CreatorAccountIndex, ZeroInt)
	IsVariableEqual(api, flag, nft.OwnerAccountIndex, ZeroInt)
	IsVariableEqual(api, flag, nft.RoyaltyRate, ZeroInt)
	IsVariableEqual(api, flag, nft.CollectionId, ZeroInt)
	IsVariableEqual(api, flag, nft.NftContentType, ZeroInt)
}

/*
SetNftWitness: set nft witness
*/
func SetNftWitness(nft *Nft) (witness NftConstraints, err error) {
	if nft == nil {
		log.Println("[SetNftWitness] invalid params")
		return witness, errors.New("[SetNftWitness] invalid params")
	}
	// set witness
	witness = NftConstraints{
		NftIndex:            nft.NftIndex,
		NftContentHash:      GetNftContentHashFromBytes(nft.NftContentHash),
		CreatorAccountIndex: nft.CreatorAccountIndex,
		OwnerAccountIndex:   nft.OwnerAccountIndex,
		RoyaltyRate:         nft.RoyaltyRate,
		CollectionId:        nft.CollectionId,
		NftContentType:      nft.NftContentType,
	}
	return witness, nil
}
