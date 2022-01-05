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

package transactions

import (
	"github.com/zecrey-labs/zecrey-crypto/zecrey/circuit/bn254/std"
	"github.com/zecrey-labs/zecrey-crypto/zecrey/twistededwards/tebn254/zecrey"
	"math/big"
)

type AccountAsset struct {
	AssetId    uint64
	BalanceEnc *zecrey.ElGamalEnc
}

func EmptyAccountAsset() *AccountAsset {
	return &AccountAsset{
		AssetId:    std.ZeroInt,
		BalanceEnc: std.ZeroElgamalEnc,
	}
}

type AccountAssetLock struct {
	ChainId      uint64
	AssetId      uint64
	LockedAmount uint64
}

func EmptyAccountAssetLock() *AccountAssetLock {
	return &AccountAssetLock{
		ChainId:      std.ZeroInt,
		AssetId:      std.ZeroInt,
		LockedAmount: std.ZeroInt,
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
		PairIndex: std.ZeroInt,
		AssetA:    std.ZeroInt,
		AssetB:    std.ZeroInt,
		AssetAR:   std.ZeroBigInt,
		AssetBR:   std.ZeroBigInt,
		LpEnc:     std.ZeroElgamalEnc,
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
	AssetsInfo              [NbAccountAssetsPerAccount]*AccountAsset
	LockedAssetInfo         *AccountAssetLock
	LiquidityInfo           *AccountLiquidity
}

func EmptyAccount(nilHash []byte) *Account {
	return &Account{
		AccountIndex:            std.ZeroInt,
		AccountName:             std.ZeroBigInt,
		AccountPk:               std.ZeroPoint,
		StateRoot:               nilHash,
		AccountAssetsRoot:       nilHash,
		AccountLockedAssetsRoot: nilHash,
		AccountLiquidityRoot:    nilHash,
		AssetsInfo: [3]*AccountAsset{
			EmptyAccountAsset(),
			EmptyAccountAsset(),
			EmptyAccountAsset(),
		},
		LockedAssetInfo: EmptyAccountAssetLock(),
		LiquidityInfo:   EmptyAccountLiquidity(),
	}
}
