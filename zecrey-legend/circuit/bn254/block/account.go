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

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"math/big"
)

/*
	Account: account info
*/
type Account struct {
	AccountIndex      uint64
	AccountName       *big.Int
	AccountPk         *eddsa.PublicKey
	Nonce             uint64
	StateRoot         []byte
	AccountAssetsRoot []byte
	AccountNftRoot    []byte
	AssetsInfo        [NbAccountAssetsPerAccount]*AccountAsset
	NftInfo           *AccountNft
}

/*
	AccountAsset: asset info
*/
type AccountAsset struct {
	Index      uint64
	BalanceEnc *big.Int
	AssetAId   uint64
	AssetBId   uint64
	AssetA     *big.Int
	AssetB     *big.Int
	LpAmount   *big.Int
}

/*
	AccountNft: nft info
*/
type AccountNft struct {
	NftIndex       uint64
	CreatorIndex   uint64
	NftContentHash []byte
	AssetId        uint64
	AssetAmount    uint64
	ChainId        uint64
	L1Address      string
	L1TokenId      uint64
}
