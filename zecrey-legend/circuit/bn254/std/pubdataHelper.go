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

func CollectPubDataFromRegisterZNS(api API, flag Variable, txInfo RegisterZnsTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeRegisterZns, TxTypeBitsSize)
		accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
		accountNameBits := api.ToBinary(txInfo.AccountName, AccountNameBitsSize)
		accountNameHashBits := api.ToBinary(txInfo.AccountNameHash, AccountNameHashBitsSize)
		pubKeyBits := api.ToBinary(txInfo.PubKey, PubKeyBitsSize)
		ABits := append(accountIndexBits[8:], txTypeBits...)
		BBits := append(accountNameBits[8:], accountIndexBits[:8]...)
		CBits := append(accountNameHashBits[8:], accountNameBits[:8]...)
		DBits := append(pubKeyBits[8:], accountNameHashBits[:8]...)
		EBits := pubKeyBits[:8]
		A := api.FromBinary(ABits)
		B := api.FromBinary(BBits)
		C := api.FromBinary(CBits)
		D := api.FromBinary(DBits)
		E := api.FromBinary(EBits)
		hFunc.Write(A, B, C, D, E)
	}
}

func CollectPubDataFromCreatePair(api API, flag Variable, txInfo CreatePairTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeCreatePair, TxTypeBitsSize)
		pairIndexBits := api.ToBinary(txInfo.PairIndex, PairIndexBitsSize)
		assetAIdBits := api.ToBinary(txInfo.AssetAId, AssetIdBitsSize)
		assetBIdBits := api.ToBinary(txInfo.AssetBId, AssetIdBitsSize)
		ABits := append(pairIndexBits, txTypeBits...)
		ABits = append(assetAIdBits, ABits...)
		ABits = append(assetBIdBits, ABits...)
		A := api.FromBinary(ABits)
		hFunc.Write(A)
	}
}

func CollectPubDataFromDeposit(api API, flag Variable, txInfo DepositTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeCreatePair, TxTypeBitsSize)
		accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
		accountNameHashBits := api.ToBinary(txInfo.AccountNameHash, AccountNameHashBitsSize)
		assetIdBits := api.ToBinary(txInfo.AssetId, AssetIdBitsSize)
		assetAmountBits := api.ToBinary(txInfo.AssetAmount, StateAmountBitsSize)
		ABits := append(accountIndexBits, txTypeBits...)
		ABits = append(accountNameHashBits[40:], ABits...)
		BBits := append(assetIdBits, accountNameHashBits[:40])
		BBits = append(assetAmountBits, BBits...)
		A := api.FromBinary(ABits)
		B := api.FromBinary(BBits)
		hFunc.Write(A, B)
	}
}

func CollectPubDataFromDepositNft(api API, flag Variable, txInfo DepositNftTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeDepositNft, TxTypeBitsSize)
		accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
		accountNameHashBits := api.ToBinary(txInfo.AccountNameHash, AccountNameHashBitsSize)
		nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
		nftContentHashBits := api.ToBinary(txInfo.NftContentHash, NftContentHashBitsSize)
		nftL1AddressBits := api.ToBinary(txInfo.NftL1Address, AddressBitsSize)
		nftL1TokenIdBits := api.ToBinary(txInfo.NftL1TokenId, NftL1TokenIdBitsSize)
		creatorTreasuryRateBits := api.ToBinary(txInfo.CreatorTreasuryRate, CreatorTreasuryRateBitsSize)
		ABits := append(accountIndexBits, txTypeBits...)
		ABits = append(accountNameHashBits[40:], ABits...)
		BBits := append(nftIndexBits, accountNameHashBits[:40]...)
		BBits = append(nftContentHashBits[80:], BBits...)
		CBits := append(nftL1AddressBits, nftContentHashBits[:80]...)
		CBits = append(nftL1TokenIdBits[240:], CBits...)
		DBits := append(creatorTreasuryRateBits, nftL1TokenIdBits[:240]...)
		A := api.FromBinary(ABits)
		B := api.FromBinary(BBits)
		C := api.FromBinary(CBits)
		D := api.FromBinary(DBits)
		hFunc.Write(A, B, C, D)
	}
}

func CollectPubDataFromTransfer(api API, flag Variable, txInfo TransferTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeTransfer, TxTypeBitsSize)
		fromAccountIndexBits := api.ToBinary(txInfo.FromAccountIndex, AccountIndexBitsSize)
		toAccountIndexBits := api.ToBinary(txInfo.ToAccountIndex, AccountIndexBitsSize)
		assetIdBits := api.ToBinary(txInfo.AssetId, AssetIdBitsSize)
		assetAmountBits := api.ToBinary(txInfo.AssetAmount, PackedAmountBitsSize)
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		callDataHashBits := api.ToBinary(txInfo.CallDataHash, CallDataHashBitsSize)
		ABits := append(fromAccountIndexBits, txTypeBits...)
		ABits = append(toAccountIndexBits, ABits...)
		ABits = append(assetIdBits, ABits...)
		ABits = append(assetAmountBits, ABits...)
		ABits = append(gasAccountIndexBits, ABits...)
		ABits = append(gasFeeAssetIdBits, ABits...)
		ABits = append(gasFeeAssetAmountBits, ABits...)
		ABits = append(callDataHashBits[176:], ABits...)
		BBits := callDataHashBits[:176]
		A := api.FromBinary(ABits)
		B := api.FromBinary(BBits)
		hFunc.Write(A, B)
	}
}

func CollectPubDataFromSwap(api API, flag Variable, txInfo SwapTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeSwap, TxTypeBitsSize)
		fromAccountIndexBits := api.ToBinary(txInfo.FromAccountIndex, AccountIndexBitsSize)
		pairIndexBits := api.ToBinary(txInfo.PairIndex, PairIndexBitsSize)
		assetAAmountBits := api.ToBinary(txInfo.AssetAAmount, PackedAmountBitsSize)
		assetBAmountBits := api.ToBinary(txInfo.AssetBAmountDelta, PackedAmountBitsSize)
		treasuryAccountIndexBits := api.ToBinary(txInfo.TreasuryAccountIndex, AccountIndexBitsSize)
		treasuryFeeAmountBits := api.ToBinary(txInfo.TreasuryFeeAmountDelta, PackedFeeBitsSize)
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		ABits := append(fromAccountIndexBits, txTypeBits...)
		ABits = append(pairIndexBits, ABits...)
		ABits = append(assetAAmountBits, ABits...)
		ABits = append(assetBAmountBits, ABits...)
		ABits = append(treasuryAccountIndexBits, ABits...)
		ABits = append(treasuryFeeAmountBits, ABits...)
		ABits = append(gasAccountIndexBits, ABits...)
		ABits = append(gasFeeAssetIdBits, ABits...)
		ABits = append(gasFeeAssetAmountBits, ABits...)
		A := api.FromBinary(ABits)
		hFunc.Write(A)
	}
}

func CollectPubDataFromAddLiquidity(api API, flag Variable, txInfo AddLiquidityTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeAddLiquidity, TxTypeBitsSize)
		fromAccountIndexBits := api.ToBinary(txInfo.FromAccountIndex, AccountIndexBitsSize)
		pairIndexBits := api.ToBinary(txInfo.PairIndex, PairIndexBitsSize)
		assetAAmountBits := api.ToBinary(txInfo.AssetAAmount, PackedAmountBitsSize)
		assetBAmountBits := api.ToBinary(txInfo.AssetBAmount, PackedAmountBitsSize)
		lpAmountBits := api.ToBinary(txInfo.LpAmount, PackedAmountBitsSize)
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		ABits := append(fromAccountIndexBits, txTypeBits...)
		ABits = append(pairIndexBits, ABits...)
		ABits = append(assetAAmountBits, ABits...)
		ABits = append(assetBAmountBits, ABits...)
		ABits = append(lpAmountBits, ABits...)
		ABits = append(gasAccountIndexBits, ABits...)
		ABits = append(gasFeeAssetIdBits, ABits...)
		ABits = append(gasFeeAssetAmountBits, ABits...)
		A := api.FromBinary(ABits)
		hFunc.Write(A)
	}
}

func CollectPubDataFromRemoveLiquidity(api API, flag Variable, txInfo RemoveLiquidityTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeRemoveLiquidity, TxTypeBitsSize)
		fromAccountIndexBits := api.ToBinary(txInfo.FromAccountIndex, AccountIndexBitsSize)
		pairIndexBits := api.ToBinary(txInfo.PairIndex, PairIndexBitsSize)
		assetAAmountBits := api.ToBinary(txInfo.AssetAAmountDelta, PackedAmountBitsSize)
		assetBAmountBits := api.ToBinary(txInfo.AssetBAmountDelta, PackedAmountBitsSize)
		lpAmountBits := api.ToBinary(txInfo.LpAmount, PackedAmountBitsSize)
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		ABits := append(fromAccountIndexBits, txTypeBits...)
		ABits = append(pairIndexBits, ABits...)
		ABits = append(assetAAmountBits, ABits...)
		ABits = append(assetBAmountBits, ABits...)
		ABits = append(lpAmountBits, ABits...)
		ABits = append(gasAccountIndexBits, ABits...)
		ABits = append(gasFeeAssetIdBits, ABits...)
		ABits = append(gasFeeAssetAmountBits, ABits...)
		A := api.FromBinary(ABits)
		hFunc.Write(A)
	}
}

func CollectPubDataFromWithdraw(api API, flag Variable, txInfo WithdrawTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeWithdraw, TxTypeBitsSize)
		fromAccountIndexBits := api.ToBinary(txInfo.FromAccountIndex, AccountIndexBitsSize)
		toAddressBits := api.ToBinary(txInfo.ToAddress, AddressBitsSize)
		assetIdBits := api.ToBinary(txInfo.AssetId, AssetIdBitsSize)
		assetAmountBits := api.ToBinary(txInfo.AssetAmount, StateAmountBitsSize)
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		ABits := append(fromAccountIndexBits, txTypeBits...)
		ABits = append(toAddressBits, ABits...)
		ABits = append(assetIdBits, ABits...)
		ABits = append(assetAmountBits[88:], ABits...)
		BBits := append(gasAccountIndexBits, assetAmountBits[:88])
		BBits = append(gasFeeAssetIdBits, BBits...)
		BBits = append(gasFeeAssetAmountBits, BBits...)
		A := api.FromBinary(ABits)
		B := api.FromBinary(BBits)
		hFunc.Write(A, B)
	}
}

func CollectPubDataFromMintNft(api API, flag Variable, txInfo MintNftTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeMintNft, TxTypeBitsSize)
		fromAccountIndexBits := api.ToBinary(txInfo.CreatorAccountIndex, AccountIndexBitsSize)
		toAccountIndexBits := api.ToBinary(txInfo.ToAccountIndex, AccountIndexBitsSize)
		nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
		nftContentHashBits := api.ToBinary(txInfo.NftContentHash, NftContentHashBitsSize)
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		creatorTreasuryRateBits := api.ToBinary(txInfo.CreatorTreasuryRate, CreatorTreasuryRateBitsSize)
		ABits := append(fromAccountIndexBits, txTypeBits...)
		ABits = append(toAccountIndexBits, ABits...)
		ABits = append(nftIndexBits, ABits...)
		ABits = append(nftContentHashBits[112:], ABits...)
		BBits := append(gasAccountIndexBits, nftContentHashBits[:112])
		BBits = append(gasFeeAssetIdBits, BBits...)
		BBits = append(gasFeeAssetAmountBits, BBits...)
		BBits = append(creatorTreasuryRateBits, BBits...)
		A := api.FromBinary(ABits)
		B := api.FromBinary(BBits)
		hFunc.Write(A, B)
	}
}

func CollectPubDataFromTransferNft(api API, flag Variable, txInfo TransferNftTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeTransferNft, TxTypeBitsSize)
		fromAccountIndexBits := api.ToBinary(txInfo.FromAccountIndex, AccountIndexBitsSize)
		toAccountIndexBits := api.ToBinary(txInfo.ToAccountIndex, AccountIndexBitsSize)
		nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		callDataHashBits := api.ToBinary(txInfo.CallDataHash, CallDataHashBitsSize)
		ABits := append(fromAccountIndexBits, txTypeBits...)
		ABits = append(toAccountIndexBits, ABits...)
		ABits = append(nftIndexBits, ABits...)
		ABits = append(gasAccountIndexBits, ABits)
		ABits = append(gasFeeAssetIdBits, ABits...)
		ABits = append(gasFeeAssetAmountBits, ABits...)
		ABits = append(callDataHashBits[176:], ABits...)
		BBits := callDataHashBits[:176]
		A := api.FromBinary(ABits)
		B := api.FromBinary(BBits)
		hFunc.Write(A, B)
	}
}

func CollectPubDataFromSetNftPrice(api API, flag Variable, txInfo SetNftPriceTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeSetNftPrice, TxTypeBitsSize)
		fromAccountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
		nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
		assetIdBits := api.ToBinary(txInfo.AssetId, AssetIdBitsSize)
		assetAmountBits := api.ToBinary(txInfo.AssetAmount, PackedAmountBitsSize)
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		ABits := append(fromAccountIndexBits, txTypeBits...)
		ABits = append(nftIndexBits, ABits...)
		ABits = append(assetIdBits, ABits...)
		ABits = append(assetAmountBits, ABits...)
		ABits = append(gasAccountIndexBits, ABits)
		ABits = append(gasFeeAssetIdBits, ABits...)
		ABits = append(gasFeeAssetAmountBits, ABits...)
		A := api.FromBinary(ABits)
		hFunc.Write(A)
	}
}

func CollectPubDataFromBuyNft(api API, flag Variable, txInfo BuyNftTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeBuyNft, TxTypeBitsSize)
		buyerAccountIndexBits := api.ToBinary(txInfo.BuyerAccountIndex, AccountIndexBitsSize)
		ownerAccountIndexBits := api.ToBinary(txInfo.OwnerAccountIndex, AccountIndexBitsSize)
		nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
		assetIdBits := api.ToBinary(txInfo.AssetId, AssetIdBitsSize)
		assetAmountBits := api.ToBinary(txInfo.AssetAmount, PackedAmountBitsSize)
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		treasuryFeeAccountIndexBits := api.ToBinary(txInfo.TreasuryAccountIndex, AccountIndexBitsSize)
		treasuryFeeAmountBits := api.ToBinary(txInfo.TreasuryFeeAmount, PackedFeeBitsSize)
		creatorTreasuryAmountBits := api.ToBinary(txInfo.CreatorTreasuryAmount, PackedFeeBitsSize)
		ABits := append(buyerAccountIndexBits, txTypeBits...)
		ABits = append(ownerAccountIndexBits, ABits...)
		ABits = append(nftIndexBits, ABits...)
		ABits = append(assetIdBits, ABits...)
		ABits = append(assetAmountBits, ABits...)
		ABits = append(gasAccountIndexBits, ABits)
		ABits = append(gasFeeAssetIdBits, ABits...)
		ABits = append(gasFeeAssetAmountBits, ABits...)
		ABits = append(treasuryFeeAccountIndexBits[8:], ABits...)
		BBits := append(treasuryFeeAmountBits, treasuryFeeAccountIndexBits[:8])
		BBits = append(creatorTreasuryAmountBits, BBits...)
		A := api.FromBinary(ABits)
		B := api.FromBinary(BBits)
		hFunc.Write(A, B)
	}
}

func CollectPubDataFromWithdrawNft(api API, flag Variable, txInfo WithdrawNftTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeWithdrawNft, TxTypeBitsSize)
		accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
		nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
		nftContentHashBits := api.ToBinary(txInfo.NftContentHash, NftContentHashBitsSize)
		nftL1AddressBits := api.ToBinary(txInfo.NftL1Address, AddressBitsSize)
		nftL1TokenIdBits := api.ToBinary(txInfo.NftL1TokenId, NftL1TokenIdBitsSize)
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		ABits := append(accountIndexBits, txTypeBits...)
		ABits = append(nftIndexBits, ABits...)
		ABits = append(nftContentHashBits[80:], ABits...)
		BBits := append(nftL1AddressBits, nftContentHashBits[:80])
		BBits = append(nftL1TokenIdBits[240:], BBits...)
		CBits := append(gasAccountIndexBits[16:], nftL1TokenIdBits[:240])
		DBits := append(gasFeeAssetIdBits, gasAccountIndexBits[:16])
		DBits = append(gasFeeAssetAmountBits, DBits...)
		A := api.FromBinary(ABits)
		B := api.FromBinary(BBits)
		C := api.FromBinary(CBits)
		D := api.FromBinary(DBits)
		hFunc.Write(A, B, C, D)
	}
}

func CollectPubDataFromFullExit(api API, flag Variable, txInfo FullExitTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeFullExit, TxTypeBitsSize)
		accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
		accountNameHashBits := api.ToBinary(txInfo.AccountNameHash, AccountNameHashBitsSize)
		assetIdBits := api.ToBinary(txInfo.AssetId, AssetIdBitsSize)
		assetAmountBits := api.ToBinary(txInfo.AssetAmount, StateAmountBitsSize)
		ABits := append(accountIndexBits, txTypeBits...)
		ABits = append(accountNameHashBits[40:], ABits...)
		BBits := append(assetIdBits, accountNameHashBits[:40])
		BBits = append(assetAmountBits, BBits...)
		A := api.FromBinary(ABits)
		B := api.FromBinary(BBits)
		hFunc.Write(A, B)
	}
}

func CollectPubDataFromFullExitNft(api API, flag Variable, txInfo FullExitNftTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeFullExitNft, TxTypeBitsSize)
		accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
		nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
		nftContentHashBits := api.ToBinary(txInfo.NftContentHash, NftContentHashBitsSize)
		nftL1AddressBits := api.ToBinary(txInfo.NftL1Address, AddressBitsSize)
		nftL1TokenIdBits := api.ToBinary(txInfo.NftL1TokenId, NftL1TokenIdBitsSize)
		ABits := append(accountIndexBits, txTypeBits...)
		ABits = append(nftIndexBits, ABits...)
		ABits = append(nftContentHashBits[80:], ABits...)
		BBits := append(nftL1AddressBits, nftContentHashBits[:80])
		BBits = append(nftL1TokenIdBits[240:], BBits...)
		CBits := nftL1TokenIdBits[:240]
		A := api.FromBinary(ABits)
		B := api.FromBinary(BBits)
		C := api.FromBinary(CBits)
		hFunc.Write(A, B, C)
	}
}
