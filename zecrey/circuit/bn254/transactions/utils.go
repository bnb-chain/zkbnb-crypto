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

import "zecrey-crypto/zecrey/circuit/bn254/std"

func SelectCommonPart(
	api API,
	flag Variable,
	c, cCheck Variable,
	pkProofs, pkProofsCheck [MaxRangeProofCount]std.CommonPkProof,
	tProofs, tProofsCheck [MaxRangeProofCount]std.CommonTProof,
) (cRes Variable, pkProofsRes [MaxRangeProofCount]std.CommonPkProof, tProofsRes [MaxRangeProofCount]std.CommonTProof) {
	cRes = api.Select(flag, c, cCheck)
	for i := 0; i < MaxRangeProofCount; i++ {
		pkProofsRes[i] = std.SelectCommonPkProof(api, flag, pkProofs[i], pkProofsCheck[i])
		tProofsRes[i] = std.SelectCommonTProof(api, flag, tProofs[i], tProofsCheck[i])
	}
	return cRes, pkProofsRes, tProofsRes
}

func GetAccountDeltasFromUnlockProof(
	api API, tool EccTool, h Point,
	proof UnlockProofConstraints,
) (deltas [NbAccountsPerTx]AccountDeltaConstraints) {
	// from account
	gasDeltaForGasAccount := tool.ScalarMul(h, proof.GasFee)
	gasDeltaForFromAccount := tool.Neg(gasDeltaForGasAccount)
	assetDeltaForFromAccount := tool.ScalarMul(h, proof.DeltaAmount)
	// from asset
	deltas[UnlockFromAccount] = AccountDeltaConstraints{
		AssetsDeltaInfo: [3]ElGamalEncConstraints{
			// from asset
			{
				CL: tool.ZeroPoint(),
				CR: assetDeltaForFromAccount,
			},
			// gas asset
			{
				CL: tool.ZeroPoint(),
				CR: gasDeltaForFromAccount,
			},
			{
				CL: tool.ZeroPoint(),
				CR: gasDeltaForFromAccount,
			},
		},
		// locked asset
		LockedAssetDeltaInfo: api.Neg(proof.DeltaAmount),
		LiquidityDeltaInfo: AccountLiquidityDeltaConstraints{
			AssetADelta:  api.Constant(std.ZeroInt),
			AssetBDelta:  api.Constant(std.ZeroInt),
			AssetARDelta: api.Constant(std.ZeroInt),
			AssetBRDelta: api.Constant(std.ZeroInt),
			LpEncDelta:   tool.ZeroElgamalEnc(),
		},
	}
	// gas account
	deltas[UnlockGasAccount] = AccountDeltaConstraints{
		AssetsDeltaInfo: [3]ElGamalEncConstraints{
			// gas asset
			{
				CL: tool.ZeroPoint(),
				CR: gasDeltaForGasAccount,
			},
			// gas asset
			{
				CL: tool.ZeroPoint(),
				CR: gasDeltaForGasAccount,
			},
			{
				CL: tool.ZeroPoint(),
				CR: gasDeltaForGasAccount,
			},
		},
		LockedAssetDeltaInfo: api.Constant(std.ZeroInt),
		LiquidityDeltaInfo: AccountLiquidityDeltaConstraints{
			AssetADelta:  api.Constant(std.ZeroInt),
			AssetBDelta:  api.Constant(std.ZeroInt),
			AssetARDelta: api.Constant(std.ZeroInt),
			AssetBRDelta: api.Constant(std.ZeroInt),
			LpEncDelta:   tool.ZeroElgamalEnc(),
		},
	}
	deltas[2] = deltas[UnlockGasAccount]
	deltas[3] = deltas[UnlockGasAccount]
	return deltas
}

func GetAccountDeltasFromTransferProof(
	api API, tool std.EccTool, h Point,
	proof TransferProofConstraints,
) (deltas [NbAccountsPerTx]AccountDeltaConstraints) {
	// account A
	deltas[TransferAccountA] = AccountDeltaConstraints{
		AssetsDeltaInfo: [3]ElGamalEncConstraints{
			// from asset
			proof.SubProofs[TransferAccountA].CDelta,
			proof.SubProofs[TransferAccountA].CDelta,
			proof.SubProofs[TransferAccountA].CDelta,
		},
		// locked asset
		LockedAssetDeltaInfo: api.Constant(std.ZeroInt),
		LiquidityDeltaInfo: AccountLiquidityDeltaConstraints{
			AssetADelta:  api.Constant(std.ZeroInt),
			AssetBDelta:  api.Constant(std.ZeroInt),
			AssetARDelta: api.Constant(std.ZeroInt),
			AssetBRDelta: api.Constant(std.ZeroInt),
			LpEncDelta:   tool.ZeroElgamalEnc(),
		},
	}
	// account B
	deltas[TransferAccountB] = AccountDeltaConstraints{
		AssetsDeltaInfo: [3]ElGamalEncConstraints{
			// from asset
			proof.SubProofs[TransferAccountB].CDelta,
			proof.SubProofs[TransferAccountB].CDelta,
			proof.SubProofs[TransferAccountB].CDelta,
		},
		// locked asset
		LockedAssetDeltaInfo: api.Constant(std.ZeroInt),
		LiquidityDeltaInfo: AccountLiquidityDeltaConstraints{
			AssetADelta:  api.Constant(std.ZeroInt),
			AssetBDelta:  api.Constant(std.ZeroInt),
			AssetARDelta: api.Constant(std.ZeroInt),
			AssetBRDelta: api.Constant(std.ZeroInt),
			LpEncDelta:   tool.ZeroElgamalEnc(),
		},
	}
	// account C
	deltas[TransferAccountC] = AccountDeltaConstraints{
		AssetsDeltaInfo: [3]ElGamalEncConstraints{
			// from asset
			proof.SubProofs[TransferAccountC].CDelta,
			proof.SubProofs[TransferAccountC].CDelta,
			proof.SubProofs[TransferAccountC].CDelta,
		},
		// locked asset
		LockedAssetDeltaInfo: api.Constant(std.ZeroInt),
		LiquidityDeltaInfo: AccountLiquidityDeltaConstraints{
			AssetADelta:  api.Constant(std.ZeroInt),
			AssetBDelta:  api.Constant(std.ZeroInt),
			AssetARDelta: api.Constant(std.ZeroInt),
			AssetBRDelta: api.Constant(std.ZeroInt),
			LpEncDelta:   tool.ZeroElgamalEnc(),
		},
	}
	// gas account
	gasDeltaForGasAccount := tool.ScalarMul(h, proof.GasFee)
	deltas[TransferGasAccount] = AccountDeltaConstraints{
		AssetsDeltaInfo: [3]ElGamalEncConstraints{
			// gas asset
			{CL: tool.ZeroPoint(), CR: gasDeltaForGasAccount},
			{CL: tool.ZeroPoint(), CR: gasDeltaForGasAccount},
			{CL: tool.ZeroPoint(), CR: gasDeltaForGasAccount},
		},
		// locked asset
		LockedAssetDeltaInfo: api.Constant(std.ZeroInt),
		LiquidityDeltaInfo: AccountLiquidityDeltaConstraints{
			AssetADelta:  api.Constant(std.ZeroInt),
			AssetBDelta:  api.Constant(std.ZeroInt),
			AssetARDelta: api.Constant(std.ZeroInt),
			AssetBRDelta: api.Constant(std.ZeroInt),
			LpEncDelta:   tool.ZeroElgamalEnc(),
		},
	}
	return deltas
}

func GetAccountDeltasFromSwapProof(
	api API, tool std.EccTool, h Point,
	proof SwapProofConstraints,
) (deltas [NbAccountsPerTx]AccountDeltaConstraints) {
	// from account
	gasDeltaForGasAccount := tool.ScalarMul(h, proof.GasFee)
	deltas[SwapFromAccount] = AccountDeltaConstraints{
		AssetsDeltaInfo: [3]ElGamalEncConstraints{
			// from asset
			proof.C_uA_Delta,
			// to asset
			proof.C_uB_Delta,
			// gas asset
			proof.SubProofs[TransferAccountA].CDelta,
		},
		// locked asset
		LockedAssetDeltaInfo: api.Constant(std.ZeroInt),
		LiquidityDeltaInfo: AccountLiquidityDeltaConstraints{
			AssetADelta:  api.Constant(std.ZeroInt),
			AssetBDelta:  api.Constant(std.ZeroInt),
			AssetARDelta: api.Constant(std.ZeroInt),
			AssetBRDelta: api.Constant(std.ZeroInt),
			LpEncDelta:   tool.ZeroElgamalEnc(),
		},
	}
	// pool account
	deltas[SwapPoolAccount] = AccountDeltaConstraints{
		AssetsDeltaInfo: [3]ElGamalEncConstraints{
			proof.SubProofs[TransferAccountB].CDelta,
			proof.SubProofs[TransferAccountB].CDelta,
			proof.SubProofs[TransferAccountB].CDelta,
		},
		// locked asset
		LockedAssetDeltaInfo: api.Constant(std.ZeroInt),
		// pool info
		LiquidityDeltaInfo: AccountLiquidityDeltaConstraints{
			AssetADelta:  api.Constant(std.ZeroInt),
			AssetBDelta:  api.Constant(std.ZeroInt),
			AssetARDelta: api.Constant(std.ZeroInt),
			AssetBRDelta: api.Constant(std.ZeroInt),
			LpEncDelta:   tool.ZeroElgamalEnc(),
		},
	}
	// treasury account
	deltas[SwapTreasuryAccount] = AccountDeltaConstraints{
		AssetsDeltaInfo: [3]ElGamalEncConstraints{
			// from asset
			proof.SubProofs[TransferAccountC].CDelta,
			proof.SubProofs[TransferAccountC].CDelta,
			proof.SubProofs[TransferAccountC].CDelta,
		},
		LockedAssetDeltaInfo: api.Constant(std.ZeroInt),
		LiquidityDeltaInfo: AccountLiquidityDeltaConstraints{
			AssetADelta:  api.Constant(std.ZeroInt),
			AssetBDelta:  api.Constant(std.ZeroInt),
			AssetARDelta: api.Constant(std.ZeroInt),
			AssetBRDelta: api.Constant(std.ZeroInt),
			LpEncDelta:   tool.ZeroElgamalEnc(),
		},
	}
	// gas account

	deltas[SwapGasAccount] = AccountDeltaConstraints{
		AssetsDeltaInfo: [3]ElGamalEncConstraints{
			// gas asset
			{CL: tool.ZeroPoint(), CR: gasDeltaForGasAccount},
			{CL: tool.ZeroPoint(), CR: gasDeltaForGasAccount},
			{CL: tool.ZeroPoint(), CR: gasDeltaForGasAccount},
		},
		LockedAssetDeltaInfo: api.Constant(std.ZeroInt),
		LiquidityDeltaInfo: AccountLiquidityDeltaConstraints{
			AssetADelta:  api.Constant(std.ZeroInt),
			AssetBDelta:  api.Constant(std.ZeroInt),
			AssetARDelta: api.Constant(std.ZeroInt),
			AssetBRDelta: api.Constant(std.ZeroInt),
			LpEncDelta:   tool.ZeroElgamalEnc(),
		},
	}
	return deltas
}

func GetAccountDeltasFromAddLiquidityProof(
	api API, tool std.EccTool,
	proof AddLiquidityProofConstraints,
) (deltas [NbAccountsPerTx]AccountDeltaConstraints) {
	return deltas
}

func GetAccountDeltasFromRemoveLiquidityProof(
	api API, tool std.EccTool,
	proof RemoveLiquidityProofConstraints,
) (deltas [NbAccountsPerTx]AccountDeltaConstraints) {
	return deltas
}

func GetAccountDeltasFromWithdrawProof(
	api API, tool std.EccTool,
	proof WithdrawProofConstraints,
) (deltas [NbAccountsPerTx]AccountDeltaConstraints) {
	return deltas
}
