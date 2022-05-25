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
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/zecrey-labs/zecrey-crypto/zecrey-legend/circuit/bn254/std"
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
			deltasRes[i][j].LpDelta =
				api.Select(flag, deltas[i][j].LpDelta, deltasCheck[i][j].LpDelta)
			deltasRes[i][j].OfferCanceledOrFinalized =
				api.Select(flag, deltas[i][j].OfferCanceledOrFinalized, deltasCheck[i][j].OfferCanceledOrFinalized)
		}
	}
	return deltasRes
}

func SelectLiquidityDelta(
	api API,
	flag Variable,
	delta, deltaCheck LiquidityDeltaConstraints,
) (deltaRes LiquidityDeltaConstraints) {
	deltaRes.AssetAId = api.Select(flag, delta.AssetAId, deltaCheck.AssetAId)
	deltaRes.AssetADelta = api.Select(flag, delta.AssetADelta, deltaCheck.AssetADelta)
	deltaRes.AssetBId = api.Select(flag, delta.AssetBId, deltaCheck.AssetBId)
	deltaRes.AssetBDelta = api.Select(flag, delta.AssetBDelta, deltaCheck.AssetBDelta)
	deltaRes.LpDelta = api.Select(flag, delta.LpDelta, deltaCheck.LpDelta)
	deltaRes.KLast = api.Select(flag, delta.KLast, deltaCheck.KLast)
	deltaRes.FeeRate = api.Select(flag, delta.FeeRate, deltaCheck.FeeRate)
	deltaRes.TreasuryAccountIndex = api.Select(flag, delta.TreasuryAccountIndex, deltaCheck.TreasuryAccountIndex)
	deltaRes.TreasuryRate = api.Select(flag, delta.TreasuryRate, deltaCheck.TreasuryRate)
	return deltaRes
}

func SelectNftDeltas(
	api API,
	flag Variable,
	delta, deltaCheck NftDeltaConstraints,
) (deltaRes NftDeltaConstraints) {
	deltaRes.CreatorAccountIndex = api.Select(flag, delta.CreatorAccountIndex, deltaCheck.CreatorAccountIndex)
	deltaRes.OwnerAccountIndex = api.Select(flag, delta.OwnerAccountIndex, deltaCheck.OwnerAccountIndex)
	deltaRes.NftContentHash = api.Select(flag, delta.NftContentHash, deltaCheck.NftContentHash)
	deltaRes.NftL1Address = api.Select(flag, delta.NftL1Address, deltaCheck.NftL1Address)
	deltaRes.NftL1TokenId = api.Select(flag, delta.NftL1TokenId, deltaCheck.NftL1TokenId)
	deltaRes.CreatorTreasuryRate = api.Select(flag, delta.CreatorTreasuryRate, deltaCheck.CreatorTreasuryRate)
	deltaRes.CollectionId = api.Select(flag, delta.CollectionId, deltaCheck.CollectionId)
	return deltaRes
}

func EmptySignatureWitness() (sig eddsa.Signature) {
	sig.R.X = std.ZeroInt
	sig.R.Y = std.ZeroInt
	sig.S = std.ZeroInt
	return sig
}
