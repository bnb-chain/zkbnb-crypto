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
	oEddsa "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type OfferTx struct {
	Type         int64
	OfferId      int64
	AccountIndex int64
	NftIndex     int64
	AssetId      int64
	AssetAmount  int64
	ListedAt     int64
	ExpiredAt    int64
	TreasuryRate int64
	Sig          *oEddsa.Signature
}

type OfferTxConstraints struct {
	Type         Variable
	OfferId      Variable
	AccountIndex Variable
	NftIndex     Variable
	AssetId      Variable
	AssetAmount  Variable
	ListedAt     Variable
	ExpiredAt    Variable
	TreasuryRate Variable
	Sig          eddsa.Signature
}

func EmptyOfferTxWitness() (witness OfferTxConstraints) {
	return OfferTxConstraints{
		Type:         ZeroInt,
		OfferId:      ZeroInt,
		AccountIndex: ZeroInt,
		NftIndex:     ZeroInt,
		AssetId:      ZeroInt,
		AssetAmount:  ZeroInt,
		ListedAt:     ZeroInt,
		ExpiredAt:    ZeroInt,
		TreasuryRate: ZeroInt,
		Sig: eddsa.Signature{
			R: twistededwards.Point{
				X: ZeroInt,
				Y: ZeroInt,
			},
			S: ZeroInt,
		},
	}
}

func SetSignatureWitness(sig *oEddsa.Signature) (witness eddsa.Signature) {
	return eddsa.Signature{
		R: twistededwards.Point{
			X: sig.R.X,
			Y: sig.R.Y,
		},
		S: sig.S[:],
	}
}

func SetOfferTxWitness(tx *OfferTx) (witness OfferTxConstraints) {
	witness = OfferTxConstraints{
		Type:         tx.Type,
		OfferId:      tx.OfferId,
		AccountIndex: tx.AccountIndex,
		NftIndex:     tx.NftIndex,
		AssetId:      tx.AssetId,
		AssetAmount:  tx.AssetAmount,
		ListedAt:     tx.ListedAt,
		ExpiredAt:    tx.ExpiredAt,
		TreasuryRate: tx.TreasuryRate,
		Sig:          SetSignatureWitness(tx.Sig),
	}
	return witness
}
