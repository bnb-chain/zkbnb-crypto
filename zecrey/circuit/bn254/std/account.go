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
	"github.com/zecrey-labs/zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
	"math/big"
)

type AccountAsset struct {
	AssetId    uint64
	BalanceEnc *zecrey.ElGamalEnc
}

func EmptyAccountAsset() *AccountAsset {
	return &AccountAsset{
		AssetId:    ZeroInt,
		BalanceEnc: ZeroElgamalEnc,
	}
}

type AccountAssetLock struct {
	ChainId      uint64
	AssetId      uint64
	LockedAmount uint64
}

func EmptyAccountAssetLock() *AccountAssetLock {
	return &AccountAssetLock{
		ChainId:      ZeroInt,
		AssetId:      ZeroInt,
		LockedAmount: ZeroInt,
	}
}

type AccountLiquidity struct {
	PairIndex uint64
	AssetAId  uint64
	AssetBId  uint64
	AssetA    uint64
	AssetB    uint64
	AssetAR   *big.Int
	AssetBR   *big.Int
	LpEnc     *zecrey.ElGamalEnc
}

func EmptyAccountLiquidity() *AccountLiquidity {
	return &AccountLiquidity{
		PairIndex: ZeroInt,
		AssetA:    ZeroInt,
		AssetB:    ZeroInt,
		AssetAR:   ZeroBigInt,
		AssetBR:   ZeroBigInt,
		LpEnc:     ZeroElgamalEnc,
	}
}

type AccountNft struct {
	NftAccountIndex uint64
	NftIndex        uint64
	CreatorIndex    uint64
	NftContentHash  []byte
	AssetId         uint64
	AssetAmount     uint64
	ChainId         uint64
	L1Address       string
	L1TokenId       *big.Int
}

func EmptyAccountNft() *AccountNft {
	return &AccountNft{
		NftAccountIndex: ZeroInt,
		NftIndex:        ZeroInt,
		CreatorIndex:    ZeroInt,
		NftContentHash:  []byte{},
		AssetId:         ZeroInt,
		AssetAmount:     ZeroInt,
		ChainId:         ZeroInt,
		L1Address:       "",
		L1TokenId:       ZeroBigInt,
	}
}

type Account struct {
	AccountIndex            uint64
	AccountName             *big.Int
	AccountPk               *zecrey.Point
	StateRoot               []byte
	AccountAssetsRoot       []byte
	AccountLockedAssetsRoot []byte
	AccountLiquidityRoot    []byte
	AccountNftRoot          []byte
	AssetsInfo              [NbAccountAssetsPerAccount]*AccountAsset
	LockedAssetInfo         *AccountAssetLock
	LiquidityInfo           *AccountLiquidity
	NftInfo                 *AccountNft
}

func EmptyAccount(nilHash []byte) *Account {
	return &Account{
		AccountIndex:            ZeroInt,
		AccountName:             ZeroBigInt,
		AccountPk:               ZeroPoint,
		StateRoot:               nilHash,
		AccountAssetsRoot:       nilHash,
		AccountLockedAssetsRoot: nilHash,
		AccountLiquidityRoot:    nilHash,
		AccountNftRoot:          nilHash,
		AssetsInfo: [NbAccountAssetsPerAccount]*AccountAsset{
			EmptyAccountAsset(),
			EmptyAccountAsset(),
			EmptyAccountAsset(),
		},
		LockedAssetInfo: EmptyAccountAssetLock(),
		LiquidityInfo:   EmptyAccountLiquidity(),
		NftInfo:         EmptyAccountNft(),
	}
}
