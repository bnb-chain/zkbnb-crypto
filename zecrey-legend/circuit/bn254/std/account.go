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
	"math/big"
)

/*
	Account: account info
*/
type Account struct {
	AccountIndex         uint64
	AccountName          *big.Int
	AccountPk            *eddsa.PublicKey
	Nonce                uint64
	StateRoot            []byte
	AccountAssetsRoot    []byte
	AccountNftRoot       []byte
	AccountLiquidityRoot []byte
	AssetsInfo           [NbAccountAssetsPerAccount]*AccountAsset
	LiquidityInfo        *AccountLiquidity
	NftInfo              *AccountNft
}

/*
	AccountAsset: asset info
*/
type AccountAsset struct {
	AssetId uint64
	Balance uint64
}

type AccountLiquidity struct {
	PairIndex    uint64
	AssetAId     uint32
	AssetAAmount uint64
	AssetBId     uint32
	AssetBAmount uint64
	LpAmount     uint64
}

/*
	AccountNft: nft info
*/
type AccountNft struct {
	NftAssetId     uint64
	NftIndex       uint64
	CreatorIndex   uint64
	NftContentHash []byte
	AssetId        uint64
	AssetAmount    uint64
	ChainId        uint64
	L1Address      string
	L1TokenId      uint64
}
