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

type Nft struct {
	NftIndex            int64
	NftContentHash      []byte
	CreatorAccountIndex int64
	OwnerAccountIndex   int64
	CreatorTreasuryRate int64
	CollectionId        int64
}

func EmptyNft(nftIndex int64) *Nft {
	return &Nft{
		NftIndex:            nftIndex,
		NftContentHash:      []byte{0},
		CreatorAccountIndex: 0,
		OwnerAccountIndex:   0,
		CreatorTreasuryRate: 0,
		CollectionId:        0,
	}
}
