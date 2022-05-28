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
		ABits := append(accountIndexBits, txTypeBits...)
		A := api.FromBinary(ABits...)
		B := txInfo.AccountName
		C := txInfo.AccountNameHash
		D := txInfo.PubKey.A.X
		hFunc.Write(A, B, C, D)
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
		FeeRateBits := api.ToBinary(txInfo.FeeRate, PackedFeeBitsSize)
		TreasuryAccountIndexBits := api.ToBinary(txInfo.TreasuryAccountIndex, AccountIndexBitsSize)
		TreasuryRateBits := api.ToBinary(txInfo.TreasuryRate, PackedFeeBitsSize)
		ABits := append(pairIndexBits, txTypeBits...)
		ABits = append(assetAIdBits, ABits...)
		ABits = append(assetBIdBits, ABits...)
		ABits = append(FeeRateBits, ABits...)
		ABits = append(TreasuryAccountIndexBits, ABits...)
		ABits = append(TreasuryRateBits, ABits...)
		A := api.FromBinary(ABits...)
		hFunc.Write(A)
	}
}

func CollectPubDataFromUpdatePairRate(api API, flag Variable, txInfo UpdatePairRateTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeCreatePair, TxTypeBitsSize)
		pairIndexBits := api.ToBinary(txInfo.PairIndex, PairIndexBitsSize)
		FeeRateBits := api.ToBinary(txInfo.FeeRate, PackedFeeBitsSize)
		TreasuryAccountIndexBits := api.ToBinary(txInfo.TreasuryAccountIndex, AccountIndexBitsSize)
		TreasuryRateBits := api.ToBinary(txInfo.TreasuryRate, PackedFeeBitsSize)
		ABits := append(pairIndexBits, txTypeBits...)
		ABits = append(FeeRateBits, ABits...)
		ABits = append(TreasuryAccountIndexBits, ABits...)
		ABits = append(TreasuryRateBits, ABits...)
		A := api.FromBinary(ABits...)
		hFunc.Write(A)
	}
}

func CollectPubDataFromDeposit(api API, flag Variable, txInfo DepositTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeDeposit, TxTypeBitsSize)
		accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
		assetIdBits := api.ToBinary(txInfo.AssetId, AssetIdBitsSize)
		assetAmountBits := api.ToBinary(txInfo.AssetAmount, StateAmountBitsSize)
		ABits := append(accountIndexBits, txTypeBits...)
		ABits = append(assetIdBits, ABits...)
		ABits = append(assetAmountBits, ABits...)
		A := api.FromBinary(ABits...)
		B := txInfo.AccountNameHash
		hFunc.Write(A, B)
	}
}

func CollectPubDataFromDepositNft(api API, flag Variable, txInfo DepositNftTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeDepositNft, TxTypeBitsSize)
		accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
		nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
		nftL1AddressBits := api.ToBinary(txInfo.NftL1Address, AddressBitsSize)
		creatorTreasuryRateBits := api.ToBinary(txInfo.CreatorTreasuryRate, CreatorTreasuryRateBitsSize)
		ABits := append(accountIndexBits, txTypeBits...)
		ABits = append(nftIndexBits, ABits...)
		ABits = append(nftL1AddressBits, ABits...)
		ABits = append(creatorTreasuryRateBits, ABits...)
		A := api.FromBinary(ABits...)
		B := txInfo.AccountNameHash
		C := txInfo.NftContentHash
		D := txInfo.NftL1TokenId
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
		ABits := append(fromAccountIndexBits, txTypeBits...)
		ABits = append(toAccountIndexBits, ABits...)
		ABits = append(assetIdBits, ABits...)
		ABits = append(assetAmountBits, ABits...)
		ABits = append(gasAccountIndexBits, ABits...)
		ABits = append(gasFeeAssetIdBits, ABits...)
		ABits = append(gasFeeAssetAmountBits, ABits...)
		A := api.FromBinary(ABits...)
		B := txInfo.CallDataHash
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
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		ABits := append(fromAccountIndexBits, txTypeBits...)
		ABits = append(pairIndexBits, ABits...)
		ABits = append(assetAAmountBits, ABits...)
		ABits = append(assetBAmountBits, ABits...)
		ABits = append(gasAccountIndexBits, ABits...)
		ABits = append(gasFeeAssetIdBits, ABits...)
		ABits = append(gasFeeAssetAmountBits, ABits...)
		A := api.FromBinary(ABits...)
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
		kLastBits := api.ToBinary(txInfo.KLast, PackedAmountBitsSize)
		treasuryAmountBits := api.ToBinary(txInfo.TreasuryAmount, PackedAmountBitsSize)
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		ABits := append(fromAccountIndexBits, txTypeBits...)
		ABits = append(pairIndexBits, ABits...)
		ABits = append(assetAAmountBits, ABits...)
		ABits = append(assetBAmountBits, ABits...)
		ABits = append(lpAmountBits, ABits...)
		ABits = append(kLastBits, ABits...)
		BBits := append(gasAccountIndexBits, treasuryAmountBits...)
		BBits = append(gasFeeAssetIdBits, ABits...)
		BBits = append(gasFeeAssetAmountBits, ABits...)
		A := api.FromBinary(ABits...)
		B := api.FromBinary(BBits...)
		hFunc.Write(A, B)
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
		kLastBits := api.ToBinary(txInfo.KLast, PackedAmountBitsSize)
		treasuryAmountBits := api.ToBinary(txInfo.TreasuryAmount, PackedAmountBitsSize)
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		ABits := append(fromAccountIndexBits, txTypeBits...)
		ABits = append(pairIndexBits, ABits...)
		ABits = append(assetAAmountBits, ABits...)
		ABits = append(assetBAmountBits, ABits...)
		ABits = append(lpAmountBits, ABits...)
		ABits = append(kLastBits, ABits...)
		BBits := append(gasAccountIndexBits, treasuryAmountBits...)
		BBits = append(gasFeeAssetIdBits, ABits...)
		BBits = append(gasFeeAssetAmountBits, ABits...)
		A := api.FromBinary(ABits...)
		B := api.FromBinary(BBits...)
		hFunc.Write(A, B)
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
		BBits := append(gasAccountIndexBits, assetAmountBits...)
		BBits = append(gasFeeAssetIdBits, BBits...)
		BBits = append(gasFeeAssetAmountBits, BBits...)
		A := api.FromBinary(ABits...)
		B := api.FromBinary(BBits...)
		hFunc.Write(A, B)
	}
}

func CollectPubDataFromCreateCollection(api API, flag Variable, txInfo CreateCollectionTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeDeposit, TxTypeBitsSize)
		accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
		collectionIdBits := api.ToBinary(txInfo.CollectionId, CollectionIdBitsSize)
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		ABits := append(accountIndexBits, txTypeBits...)
		ABits = append(collectionIdBits, ABits...)
		ABits = append(gasAccountIndexBits, ABits...)
		ABits = append(gasFeeAssetIdBits, ABits...)
		ABits = append(gasFeeAssetAmountBits, ABits...)
		A := api.FromBinary(ABits...)
		hFunc.Write(A)
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
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		collectionIdBits := api.ToBinary(txInfo.CollectionId, CollectionIdBitsSize)
		creatorTreasuryRateBits := api.ToBinary(txInfo.CreatorTreasuryRate, CreatorTreasuryRateBitsSize)
		ABits := append(fromAccountIndexBits, txTypeBits...)
		ABits = append(toAccountIndexBits, ABits...)
		ABits = append(nftIndexBits, ABits...)
		ABits = append(gasAccountIndexBits, ABits...)
		ABits = append(gasFeeAssetIdBits, ABits...)
		ABits = append(gasFeeAssetAmountBits, ABits...)
		ABits = append(creatorTreasuryRateBits, ABits...)
		ABits = append(collectionIdBits, ABits...)
		A := api.FromBinary(ABits...)
		B := txInfo.NftContentHash
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
		ABits := append(fromAccountIndexBits, txTypeBits...)
		ABits = append(toAccountIndexBits, ABits...)
		ABits = append(nftIndexBits, ABits...)
		ABits = append(gasAccountIndexBits, ABits...)
		ABits = append(gasFeeAssetIdBits, ABits...)
		ABits = append(gasFeeAssetAmountBits, ABits...)
		A := api.FromBinary(ABits...)
		B := txInfo.CallDataHash
		hFunc.Write(A, B)
	}
}

func CollectPubDataFromAtomicMatch(api API, flag Variable, txInfo AtomicMatchTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeAtomicMatch, TxTypeBitsSize)
		submitterAccountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
		buyerAccountIndexBits := api.ToBinary(txInfo.BuyOffer.AccountIndex, AccountIndexBitsSize)
		buyerOfferIdBits := api.ToBinary(txInfo.BuyOffer.OfferId, OfferIdBitsSize)
		sellerAccountIndexBits := api.ToBinary(txInfo.SellOffer.AccountIndex, AccountIndexBitsSize)
		sellerOfferIdBits := api.ToBinary(txInfo.SellOffer.OfferId, OfferIdBitsSize)
		assetIdBits := api.ToBinary(txInfo.SellOffer.AssetId, AssetIdBitsSize)
		assetAmountBits := api.ToBinary(txInfo.SellOffer.AssetAmount, PackedAmountBitsSize)
		creatorAmountBits := api.ToBinary(txInfo.CreatorAmount, PackedAmountBitsSize)
		treasuryAmountBits := api.ToBinary(txInfo.TreasuryAmount, PackedAmountBitsSize)
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		ABits := append(submitterAccountIndexBits, txTypeBits...)
		ABits = append(buyerAccountIndexBits, ABits...)
		ABits = append(buyerOfferIdBits, ABits...)
		ABits = append(sellerAccountIndexBits, ABits...)
		ABits = append(sellerOfferIdBits, ABits...)
		ABits = append(assetIdBits, ABits...)
		BBits := append(creatorAmountBits, assetAmountBits...)
		BBits = append(treasuryAmountBits, BBits...)
		BBits = append(gasAccountIndexBits, BBits...)
		BBits = append(gasFeeAssetIdBits, BBits...)
		BBits = append(gasFeeAssetAmountBits, BBits...)
		A := api.FromBinary(ABits...)
		B := api.FromBinary(BBits...)
		hFunc.Write(A, B)
	}
}

func CollectPubDataFromCancelOffer(api API, flag Variable, txInfo CancelOfferTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeCancelOffer, TxTypeBitsSize)
		accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
		offerIdBits := api.ToBinary(txInfo.OfferId, OfferIdBitsSize)
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		ABits := append(accountIndexBits, txTypeBits...)
		ABits = append(offerIdBits, ABits...)
		ABits = append(gasAccountIndexBits, ABits...)
		ABits = append(gasFeeAssetIdBits, ABits...)
		ABits = append(gasFeeAssetAmountBits, ABits...)
		A := api.FromBinary(ABits...)
		hFunc.Write(A)
	}
}

func CollectPubDataFromWithdrawNft(api API, flag Variable, txInfo WithdrawNftTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeWithdrawNft, TxTypeBitsSize)
		accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
		creatorAccountIndexBits := api.ToBinary(txInfo.CreatorAccountIndex, AccountIndexBitsSize)
		creatorTreasuryRateBits := api.ToBinary(txInfo.CreatorTreasuryRate, FeeRateBitsSize)
		nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
		toAddressBits := api.ToBinary(txInfo.ToAddress, AddressBitsSize)
		gasAccountIndexBits := api.ToBinary(txInfo.GasAccountIndex, AccountIndexBitsSize)
		gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
		gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
		ABits := append(accountIndexBits, txTypeBits...)
		ABits = append(creatorAccountIndexBits, ABits...)
		ABits = append(creatorTreasuryRateBits, ABits...)
		ABits = append(nftIndexBits, ABits...)
		A := api.FromBinary(ABits...)
		B := txInfo.NftL1Address
		CBits := append(gasAccountIndexBits, toAddressBits...)
		CBits = append(gasFeeAssetIdBits, CBits...)
		CBits = append(gasFeeAssetAmountBits, CBits...)
		C := api.FromBinary(CBits...)
		D := txInfo.NftContentHash
		E := txInfo.NftL1TokenId
		F := txInfo.CreatorAccountNameHash
		hFunc.Write(A, B, C, D, E, F)
	}
}

func CollectPubDataFromFullExit(api API, flag Variable, txInfo FullExitTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeFullExit, TxTypeBitsSize)
		accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
		assetIdBits := api.ToBinary(txInfo.AssetId, AssetIdBitsSize)
		assetAmountBits := api.ToBinary(txInfo.AssetAmount, StateAmountBitsSize)
		ABits := append(accountIndexBits, txTypeBits...)
		ABits = append(assetIdBits, ABits...)
		ABits = append(assetAmountBits, ABits...)
		A := api.FromBinary(ABits...)
		B := txInfo.AccountNameHash
		hFunc.Write(A, B)
	}
}

func CollectPubDataFromFullExitNft(api API, flag Variable, txInfo FullExitNftTxConstraints, hFunc *MiMC) {
	isTxVar := api.Sub(flag, 1)
	isTx := api.Compiler().IsBoolean(isTxVar)
	if isTx {
		txTypeBits := api.ToBinary(TxTypeFullExitNft, TxTypeBitsSize)
		accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
		creatorAccountIndexBits := api.ToBinary(txInfo.CreatorAccountIndex, AccountIndexBitsSize)
		creatorTreasuryRateBits := api.ToBinary(txInfo.CreatorTreasuryRate, FeeRateBitsSize)
		nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
		collectionIdBits := api.ToBinary(txInfo.CollectionId, CollectionIdBitsSize)
		ABits := append(accountIndexBits, txTypeBits...)
		ABits = append(creatorAccountIndexBits, ABits...)
		ABits = append(creatorTreasuryRateBits, ABits...)
		ABits = append(nftIndexBits, ABits...)
		ABits = append(collectionIdBits, ABits...)
		A := api.FromBinary(ABits...)
		B := txInfo.NftL1Address
		C := txInfo.AccountNameHash
		D := txInfo.CreatorAccountNameHash
		E := txInfo.NftContentHash
		F := txInfo.NftL1TokenId
		hFunc.Write(A, B, C, D, E, F)
	}
}
