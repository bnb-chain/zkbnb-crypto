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
	"github.com/consensys/gnark/std/signature/eddsa"

	"github.com/bnb-chain/zkbnb-crypto/circuit/types"
)

func SelectAssetDeltas(
	api API,
	flag Variable,
	deltas, deltasCheck [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints,
) (deltasRes [NbAccountsPerTx][NbAccountAssetsPerAccount]AccountAssetDeltaConstraints) {
	for i := 0; i < NbAccountsPerTx; i++ {
		for j := 0; j < NbAccountAssetsPerAccount; j++ {
			deltasRes[i][j].BalanceDelta =
				api.Select(flag, deltas[i][j].BalanceDelta, deltasCheck[i][j].BalanceDelta)
			deltasRes[i][j].OfferCanceledOrFinalized =
				api.Select(flag, deltas[i][j].OfferCanceledOrFinalized, deltasCheck[i][j].OfferCanceledOrFinalized)
		}
	}
	return deltasRes
}

func SelectGasDeltas(
	api API,
	flag Variable,
	deltas, deltasCheck [NbGasAssetsPerTx]GasDeltaConstraints,
) (deltasRes [NbGasAssetsPerTx]GasDeltaConstraints) {
	for i := 0; i < NbGasAssetsPerTx; i++ {
		deltasRes[i].AssetId =
			api.Select(flag, deltas[i].AssetId, deltasCheck[i].AssetId)
		deltasRes[i].BalanceDelta =
			api.Select(flag, deltas[i].BalanceDelta, deltasCheck[i].BalanceDelta)
	}
	return deltasRes
}

func SelectNftDeltas(
	api API,
	flag Variable,
	delta, deltaCheck NftDeltaConstraints,
) (deltaRes NftDeltaConstraints) {
	deltaRes.CreatorAccountIndex = api.Select(flag, delta.CreatorAccountIndex, deltaCheck.CreatorAccountIndex)
	deltaRes.OwnerAccountIndex = api.Select(flag, delta.OwnerAccountIndex, deltaCheck.OwnerAccountIndex)
	deltaRes.NftContentHash[0] = api.Select(flag, delta.NftContentHash[0], deltaCheck.NftContentHash[0])
	deltaRes.NftContentHash[1] = api.Select(flag, delta.NftContentHash[1], deltaCheck.NftContentHash[1])
	deltaRes.CreatorTreasuryRate = api.Select(flag, delta.CreatorTreasuryRate, deltaCheck.CreatorTreasuryRate)
	deltaRes.CollectionId = api.Select(flag, delta.CollectionId, deltaCheck.CollectionId)
	return deltaRes
}

func SelectPubData(
	api API,
	flag Variable,
	delta, deltaCheck [types.PubDataBitsSizePerTx]Variable,
) (deltaRes [types.PubDataBitsSizePerTx]Variable) {
	for i := 0; i < types.PubDataBitsSizePerTx; i++ {
		deltaRes[i] = api.Select(flag, delta[i], deltaCheck[i])
	}
	return deltaRes
}

func EmptySignatureWitness() (sig eddsa.Signature) {
	sig.R.X = types.ZeroInt
	sig.R.Y = types.ZeroInt
	sig.S = types.ZeroInt
	return sig
}
