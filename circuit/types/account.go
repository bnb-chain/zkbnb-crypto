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
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"

	curve "github.com/bnb-chain/zkbnb-crypto/ecc/ztwistededwards/tebn254"
)

type Account struct {
	AccountIndex    int64
	L1Address       []byte
	AccountPk       *eddsa.PublicKey
	Nonce           int64
	CollectionNonce int64
	AssetRoot       []byte
	AssetsInfo      [NbAccountAssetsPerAccount]*AccountAsset
}

func EmptyAccount(accountIndex int64, assetRoot []byte) *Account {
	return &Account{
		AccountIndex: accountIndex,
		L1Address:    []byte{},
		AccountPk: &eddsa.PublicKey{
			A: curve.Point{
				X: fr.NewElement(0),
				Y: fr.NewElement(0),
			},
		},
		Nonce:           0,
		CollectionNonce: 0,
		AssetRoot:       assetRoot,
		AssetsInfo: [NbAccountAssetsPerAccount]*AccountAsset{
			EmptyAccountAsset(0),
			EmptyAccountAsset(0),
		},
	}
}

type AccountAsset struct {
	AssetId                  int64
	Balance                  *big.Int
	OfferCanceledOrFinalized *big.Int
}

func EmptyAccountAsset(assetId int64) *AccountAsset {
	return &AccountAsset{
		AssetId:                  assetId,
		Balance:                  big.NewInt(0),
		OfferCanceledOrFinalized: big.NewInt(0),
	}
}

func EmptySignature() (sig *eddsa.Signature) {
	sig = &eddsa.Signature{
		R: curve.Point{
			X: fr.NewElement(0),
			Y: fr.NewElement(0),
		},
		S: [32]byte{},
	}
	return sig
}
