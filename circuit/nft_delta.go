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

package circuit

import (
	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
)

type NftDeltaConstraints struct {
	CreatorAccountIndex Variable
	OwnerAccountIndex   Variable
	NftContentHash      [2]Variable
	CreatorTreasuryRate Variable
	CollectionId        Variable
}

func EmptyNftDeltaConstraints() NftDeltaConstraints {
	return NftDeltaConstraints{
		CreatorAccountIndex: types.ZeroInt,
		OwnerAccountIndex:   types.ZeroInt,
		NftContentHash:      [2]Variable{types.ZeroInt, types.ZeroInt},
		CreatorTreasuryRate: types.ZeroInt,
		CollectionId:        types.ZeroInt,
	}
}

func UpdateNft(
	nft NftConstraints,
	nftDelta NftDeltaConstraints,
) (nftAfter NftConstraints) {
	nftAfter = nft
	nftAfter.CreatorAccountIndex = nftDelta.CreatorAccountIndex
	nftAfter.OwnerAccountIndex = nftDelta.OwnerAccountIndex
	nftAfter.NftContentHash = nftDelta.NftContentHash
	nftAfter.CreatorTreasuryRate = nftDelta.CreatorTreasuryRate
	nftAfter.CollectionId = nftDelta.CollectionId
	return nftAfter
}
