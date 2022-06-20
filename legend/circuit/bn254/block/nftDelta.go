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

package block

import "github.com/bnb-chain/zkbas-crypto/legend/circuit/bn254/std"

type NftDeltaConstraints struct {
	CreatorAccountIndex Variable
	OwnerAccountIndex   Variable
	NftContentHash      Variable
	NftL1Address        Variable
	NftL1TokenId        Variable
	CreatorTreasuryRate Variable
	CollectionId        Variable
}

func EmptyNftDeltaConstraints() NftDeltaConstraints {
	return NftDeltaConstraints{
		CreatorAccountIndex: std.ZeroInt,
		OwnerAccountIndex:   std.ZeroInt,
		NftContentHash:      std.ZeroInt,
		NftL1Address:        std.ZeroInt,
		NftL1TokenId:        std.ZeroInt,
		CreatorTreasuryRate: std.ZeroInt,
		CollectionId:        std.ZeroInt,
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
	nftAfter.NftL1Address = nftDelta.NftL1Address
	nftAfter.NftL1TokenId = nftDelta.NftL1TokenId
	nftAfter.CreatorTreasuryRate = nftDelta.CreatorTreasuryRate
	nftAfter.CollectionId = nftDelta.CollectionId
	return nftAfter
}
