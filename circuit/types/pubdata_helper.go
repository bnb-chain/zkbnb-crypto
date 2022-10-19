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

func CollectPubDataFromRegisterZNS(api API, txInfo RegisterZnsTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	txTypeBits := api.ToBinary(TxTypeRegisterZns, TxTypeBitsSize)
	copy(pubData[currentOffset:currentOffset+TxTypeBitsSize], txTypeBits)
	currentOffset += TxTypeBitsSize

	accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], accountIndexBits)
	currentOffset += AccountIndexBitsSize

	accountNameBits := api.ToBinary(txInfo.AccountName, HashBitsSize)
	copy(pubData[currentOffset:currentOffset+HashBitsSize], accountNameBits)
	currentOffset += HashBitsSize

	accountNameHashBits := api.ToBinary(txInfo.AccountNameHash, HashBitsSize)
	copy(pubData[currentOffset:currentOffset+HashBitsSize], accountNameHashBits)
	currentOffset += HashBitsSize

	PubkeyXBits := api.ToBinary(txInfo.PubKey.A.X, PubkeyBitsSize)
	copy(pubData[currentOffset:currentOffset+PubkeyBitsSize], PubkeyXBits)
	currentOffset += PubkeyBitsSize

	PubkeyYBits := api.ToBinary(txInfo.PubKey.A.Y, PubkeyBitsSize)
	copy(pubData[currentOffset:currentOffset+PubkeyBitsSize], PubkeyYBits)
	currentOffset += PubkeyBitsSize

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromDeposit(api API, txInfo DepositTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	txTypeBits := api.ToBinary(TxTypeDeposit, TxTypeBitsSize)
	copy(pubData[currentOffset:currentOffset+TxTypeBitsSize], txTypeBits)
	currentOffset += TxTypeBitsSize

	accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], accountIndexBits)
	currentOffset += AccountIndexBitsSize

	assetIdBits := api.ToBinary(txInfo.AssetId, AssetIdBitsSize)
	copy(pubData[currentOffset:currentOffset+AssetIdBitsSize], assetIdBits)
	currentOffset += AssetIdBitsSize

	assetAmountBits := api.ToBinary(txInfo.AssetAmount, StateAmountBitsSize)
	copy(pubData[currentOffset:currentOffset+StateAmountBitsSize], assetAmountBits)
	currentOffset += StateAmountBitsSize

	accountNameHashBits := api.ToBinary(txInfo.AccountNameHash, HashBitsSize)
	copy(pubData[currentOffset:currentOffset+HashBitsSize], accountNameHashBits)
	currentOffset += HashBitsSize

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromDepositNft(api API, txInfo DepositNftTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	txTypeBits := api.ToBinary(TxTypeDepositNft, TxTypeBitsSize)
	copy(pubData[currentOffset:currentOffset+TxTypeBitsSize], txTypeBits)
	currentOffset += TxTypeBitsSize

	accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], accountIndexBits)
	currentOffset += AccountIndexBitsSize

	nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+NftIndexBitsSize], nftIndexBits)
	currentOffset += NftIndexBitsSize

	creatorAccountIndexBits := api.ToBinary(txInfo.CreatorAccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], creatorAccountIndexBits)
	currentOffset += AccountIndexBitsSize

	creatorTreasuryRateBits := api.ToBinary(txInfo.CreatorTreasuryRate, CreatorTreasuryRateBitsSize)
	copy(pubData[currentOffset:currentOffset+CreatorTreasuryRateBitsSize], creatorTreasuryRateBits)
	currentOffset += CreatorTreasuryRateBitsSize

	collectionIdBits := api.ToBinary(txInfo.CollectionId, CollectionIdBitsSize)
	copy(pubData[currentOffset:currentOffset+CollectionIdBitsSize], collectionIdBits)
	currentOffset += CollectionIdBitsSize

	nftContentHashBits := api.ToBinary(txInfo.NftContentHash, HashBitsSize)
	copy(pubData[currentOffset:currentOffset+HashBitsSize], nftContentHashBits)
	currentOffset += HashBitsSize

	accountNameHashBits := api.ToBinary(txInfo.AccountNameHash, HashBitsSize)
	copy(pubData[currentOffset:currentOffset+HashBitsSize], accountNameHashBits)
	currentOffset += HashBitsSize

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromTransfer(api API, txInfo TransferTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	txTypeBits := api.ToBinary(TxTypeTransfer, TxTypeBitsSize)
	copy(pubData[currentOffset:currentOffset+TxTypeBitsSize], txTypeBits)
	currentOffset += TxTypeBitsSize

	fromAccountIndexBits := api.ToBinary(txInfo.FromAccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], fromAccountIndexBits)
	currentOffset += AccountIndexBitsSize

	toAccountIndexBits := api.ToBinary(txInfo.ToAccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], toAccountIndexBits)
	currentOffset += AccountIndexBitsSize

	assetIdBits := api.ToBinary(txInfo.AssetId, AssetIdBitsSize)
	copy(pubData[currentOffset:currentOffset+AssetIdBitsSize], assetIdBits)
	currentOffset += AssetIdBitsSize

	assetAmountBits := api.ToBinary(txInfo.AssetAmount, PackedAmountBitsSize)
	copy(pubData[currentOffset:currentOffset+PackedAmountBitsSize], assetAmountBits)
	currentOffset += PackedAmountBitsSize

	gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
	copy(pubData[currentOffset:currentOffset+AssetIdBitsSize], gasFeeAssetIdBits)
	currentOffset += AssetIdBitsSize

	gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
	copy(pubData[currentOffset:currentOffset+PackedFeeBitsSize], gasFeeAssetAmountBits)
	currentOffset += PackedFeeBitsSize

	callDataHashBits := api.ToBinary(txInfo.CallDataHash, HashBitsSize)
	copy(pubData[currentOffset:currentOffset+HashBitsSize], callDataHashBits)
	currentOffset += HashBitsSize

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromWithdraw(api API, txInfo WithdrawTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	txTypeBits := api.ToBinary(TxTypeWithdraw, TxTypeBitsSize)
	copy(pubData[currentOffset:currentOffset+TxTypeBitsSize], txTypeBits)
	currentOffset += TxTypeBitsSize

	fromAccountIndexBits := api.ToBinary(txInfo.FromAccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], fromAccountIndexBits)
	currentOffset += AccountIndexBitsSize

	toAddressBits := api.ToBinary(txInfo.ToAddress, AddressBitsSize)
	copy(pubData[currentOffset:currentOffset+AddressBitsSize], toAddressBits)
	currentOffset += AddressBitsSize

	assetIdBits := api.ToBinary(txInfo.AssetId, AssetIdBitsSize)
	copy(pubData[currentOffset:currentOffset+AssetIdBitsSize], assetIdBits)
	currentOffset += AssetIdBitsSize

	assetAmountBits := api.ToBinary(txInfo.AssetAmount, StateAmountBitsSize)
	copy(pubData[currentOffset:currentOffset+StateAmountBitsSize], assetAmountBits)
	currentOffset += StateAmountBitsSize

	gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
	copy(pubData[currentOffset:currentOffset+AssetIdBitsSize], gasFeeAssetIdBits)
	currentOffset += AssetIdBitsSize

	gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
	copy(pubData[currentOffset:currentOffset+PackedFeeBitsSize], gasFeeAssetAmountBits)
	currentOffset += PackedFeeBitsSize

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromCreateCollection(api API, txInfo CreateCollectionTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	txTypeBits := api.ToBinary(TxTypeCreateCollection, TxTypeBitsSize)
	copy(pubData[currentOffset:currentOffset+TxTypeBitsSize], txTypeBits)
	currentOffset += TxTypeBitsSize

	accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], accountIndexBits)
	currentOffset += AccountIndexBitsSize

	collectionIdBits := api.ToBinary(txInfo.CollectionId, CollectionIdBitsSize)
	copy(pubData[currentOffset:currentOffset+CollectionIdBitsSize], collectionIdBits)
	currentOffset += CollectionIdBitsSize

	gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
	copy(pubData[currentOffset:currentOffset+AssetIdBitsSize], gasFeeAssetIdBits)
	currentOffset += AssetIdBitsSize

	gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
	copy(pubData[currentOffset:currentOffset+PackedFeeBitsSize], gasFeeAssetAmountBits)
	currentOffset += PackedFeeBitsSize

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromMintNft(api API, txInfo MintNftTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	txTypeBits := api.ToBinary(TxTypeMintNft, TxTypeBitsSize)
	copy(pubData[currentOffset:currentOffset+TxTypeBitsSize], txTypeBits)
	currentOffset += TxTypeBitsSize

	fromAccountIndexBits := api.ToBinary(txInfo.CreatorAccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], fromAccountIndexBits)
	currentOffset += AccountIndexBitsSize

	toAccountIndexBits := api.ToBinary(txInfo.ToAccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], toAccountIndexBits)
	currentOffset += AccountIndexBitsSize

	nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+NftIndexBitsSize], nftIndexBits)
	currentOffset += NftIndexBitsSize

	gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
	copy(pubData[currentOffset:currentOffset+AssetIdBitsSize], gasFeeAssetIdBits)
	currentOffset += AssetIdBitsSize

	gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
	copy(pubData[currentOffset:currentOffset+PackedFeeBitsSize], gasFeeAssetAmountBits)
	currentOffset += PackedFeeBitsSize

	collectionIdBits := api.ToBinary(txInfo.CollectionId, CollectionIdBitsSize)
	copy(pubData[currentOffset:currentOffset+CollectionIdBitsSize], collectionIdBits)
	currentOffset += CollectionIdBitsSize

	creatorTreasuryRateBits := api.ToBinary(txInfo.CreatorTreasuryRate, CreatorTreasuryRateBitsSize)
	copy(pubData[currentOffset:currentOffset+CreatorTreasuryRateBitsSize], creatorTreasuryRateBits)
	currentOffset += CreatorTreasuryRateBitsSize

	nftContentHashBits := api.ToBinary(txInfo.NftContentHash, HashBitsSize)
	copy(pubData[currentOffset:currentOffset+HashBitsSize], nftContentHashBits)
	currentOffset += HashBitsSize

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromTransferNft(api API, txInfo TransferNftTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	txTypeBits := api.ToBinary(TxTypeTransferNft, TxTypeBitsSize)
	copy(pubData[currentOffset:currentOffset+TxTypeBitsSize], txTypeBits)
	currentOffset += TxTypeBitsSize

	fromAccountIndexBits := api.ToBinary(txInfo.FromAccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], fromAccountIndexBits)
	currentOffset += AccountIndexBitsSize

	toAccountIndexBits := api.ToBinary(txInfo.ToAccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], toAccountIndexBits)
	currentOffset += AccountIndexBitsSize

	nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+NftIndexBitsSize], nftIndexBits)
	currentOffset += NftIndexBitsSize

	gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
	copy(pubData[currentOffset:currentOffset+AssetIdBitsSize], gasFeeAssetIdBits)
	currentOffset += AssetIdBitsSize

	gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
	copy(pubData[currentOffset:currentOffset+PackedFeeBitsSize], gasFeeAssetAmountBits)
	currentOffset += PackedFeeBitsSize

	callDataHashBits := api.ToBinary(txInfo.CallDataHash, HashBitsSize)
	copy(pubData[currentOffset:currentOffset+HashBitsSize], callDataHashBits)
	currentOffset += HashBitsSize

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromAtomicMatch(api API, txInfo AtomicMatchTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	txTypeBits := api.ToBinary(TxTypeAtomicMatch, TxTypeBitsSize)
	copy(pubData[currentOffset:currentOffset+TxTypeBitsSize], txTypeBits)
	currentOffset += TxTypeBitsSize

	nftIndexBits := api.ToBinary(txInfo.BuyOffer.NftIndex, NftIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+NftIndexBitsSize], nftIndexBits)
	currentOffset += NftIndexBitsSize

	submitterAccountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], submitterAccountIndexBits)
	currentOffset += AccountIndexBitsSize

	buyerAccountIndexBits := api.ToBinary(txInfo.BuyOffer.AccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], buyerAccountIndexBits)
	currentOffset += AccountIndexBitsSize

	buyerOfferIdBits := api.ToBinary(txInfo.BuyOffer.OfferId, OfferIdBitsSize)
	copy(pubData[currentOffset:currentOffset+OfferIdBitsSize], buyerOfferIdBits)
	currentOffset += OfferIdBitsSize

	sellerAccountIndexBits := api.ToBinary(txInfo.SellOffer.AccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], sellerAccountIndexBits)
	currentOffset += AccountIndexBitsSize

	sellerOfferIdBits := api.ToBinary(txInfo.SellOffer.OfferId, OfferIdBitsSize)
	copy(pubData[currentOffset:currentOffset+OfferIdBitsSize], sellerOfferIdBits)
	currentOffset += OfferIdBitsSize

	assetIdBits := api.ToBinary(txInfo.SellOffer.AssetId, AssetIdBitsSize)
	copy(pubData[currentOffset:currentOffset+AssetIdBitsSize], assetIdBits)
	currentOffset += AssetIdBitsSize

	assetAmountBits := api.ToBinary(txInfo.SellOffer.AssetAmount, PackedAmountBitsSize)
	copy(pubData[currentOffset:currentOffset+PackedAmountBitsSize], assetAmountBits)
	currentOffset += PackedAmountBitsSize

	creatorAmountBits := api.ToBinary(txInfo.CreatorAmount, PackedAmountBitsSize)
	copy(pubData[currentOffset:currentOffset+PackedAmountBitsSize], creatorAmountBits)
	currentOffset += PackedAmountBitsSize

	treasuryAmountBits := api.ToBinary(txInfo.TreasuryAmount, PackedAmountBitsSize)
	copy(pubData[currentOffset:currentOffset+PackedAmountBitsSize], treasuryAmountBits)
	currentOffset += PackedAmountBitsSize

	gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
	copy(pubData[currentOffset:currentOffset+AssetIdBitsSize], gasFeeAssetIdBits)
	currentOffset += AssetIdBitsSize

	gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
	copy(pubData[currentOffset:currentOffset+PackedFeeBitsSize], gasFeeAssetAmountBits)
	currentOffset += PackedFeeBitsSize

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromCancelOffer(api API, txInfo CancelOfferTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {
	currentOffset := 0
	txTypeBits := api.ToBinary(TxTypeCancelOffer, TxTypeBitsSize)
	copy(pubData[currentOffset:currentOffset+TxTypeBitsSize], txTypeBits)
	currentOffset += TxTypeBitsSize

	accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], accountIndexBits)
	currentOffset += AccountIndexBitsSize

	offerIdBits := api.ToBinary(txInfo.OfferId, OfferIdBitsSize)
	copy(pubData[currentOffset:currentOffset+OfferIdBitsSize], offerIdBits)
	currentOffset += OfferIdBitsSize

	gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
	copy(pubData[currentOffset:currentOffset+AssetIdBitsSize], gasFeeAssetIdBits)
	currentOffset += AssetIdBitsSize

	gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
	copy(pubData[currentOffset:currentOffset+PackedFeeBitsSize], gasFeeAssetAmountBits)
	currentOffset += PackedFeeBitsSize

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromWithdrawNft(api API, txInfo WithdrawNftTxConstraints) (pubData [PubDataSizePerTx]Variable) {
	currentOffset := 0
	txTypeBits := api.ToBinary(TxTypeWithdrawNft, TxTypeBitsSize)
	copy(pubData[currentOffset:currentOffset+TxTypeBitsSize], txTypeBits)
	currentOffset += TxTypeBitsSize

	accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], accountIndexBits)
	currentOffset += AccountIndexBitsSize

	creatorAccountIndexBits := api.ToBinary(txInfo.CreatorAccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], creatorAccountIndexBits)
	currentOffset += AccountIndexBitsSize

	creatorTreasuryRateBits := api.ToBinary(txInfo.CreatorTreasuryRate, FeeRateBitsSize)
	copy(pubData[currentOffset:currentOffset+FeeRateBitsSize], creatorTreasuryRateBits)
	currentOffset += FeeRateBitsSize

	nftIndexBits := api.ToBinary(txInfo.NftIndex, NftIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+NftIndexBitsSize], nftIndexBits)
	currentOffset += NftIndexBitsSize

	collectionIdBits := api.ToBinary(txInfo.CollectionId, CollectionIdBitsSize)
	copy(pubData[currentOffset:currentOffset+CollectionIdBitsSize], collectionIdBits)
	currentOffset += CollectionIdBitsSize

	toAddressBits := api.ToBinary(txInfo.ToAddress, AddressBitsSize)
	copy(pubData[currentOffset:currentOffset+AddressBitsSize], toAddressBits)
	currentOffset += AddressBitsSize

	gasFeeAssetIdBits := api.ToBinary(txInfo.GasFeeAssetId, AssetIdBitsSize)
	copy(pubData[currentOffset:currentOffset+AssetIdBitsSize], gasFeeAssetIdBits)
	currentOffset += AssetIdBitsSize

	gasFeeAssetAmountBits := api.ToBinary(txInfo.GasFeeAssetAmount, PackedFeeBitsSize)
	copy(pubData[currentOffset:currentOffset+PackedFeeBitsSize], gasFeeAssetAmountBits)
	currentOffset += PackedFeeBitsSize

	nftContentHashBits := api.ToBinary(txInfo.NftContentHash, HashBitsSize)
	copy(pubData[currentOffset:currentOffset+HashBitsSize], nftContentHashBits)
	currentOffset += HashBitsSize

	creatorAccountNameHashBits := api.ToBinary(txInfo.CreatorAccountNameHash, HashBitsSize)
	copy(pubData[currentOffset:currentOffset+HashBitsSize], creatorAccountNameHashBits)
	currentOffset += HashBitsSize

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromFullExit(api API, txInfo FullExitTxConstraints) (pubData [PubDataSizePerTx]Variable) {
	currentOffset := 0
	txTypeBits := api.ToBinary(TxTypeFullExit, TxTypeBitsSize)
	copy(pubData[currentOffset:currentOffset+TxTypeBitsSize], txTypeBits)
	currentOffset += TxTypeBitsSize

	accountIndexBits := api.ToBinary(txInfo.AccountIndex, AccountIndexBitsSize)
	copy(pubData[currentOffset:currentOffset+AccountIndexBitsSize], accountIndexBits)
	currentOffset += AccountIndexBitsSize

	assetIdBits := api.ToBinary(txInfo.AssetId, AssetIdBitsSize)
	copy(pubData[currentOffset:currentOffset+AssetIdBitsSize], assetIdBits)
	currentOffset += AssetIdBitsSize

	assetAmountBits := api.ToBinary(txInfo.AssetAmount, StateAmountBitsSize)
	copy(pubData[currentOffset:currentOffset+StateAmountBitsSize], assetAmountBits)
	currentOffset += StateAmountBitsSize

	accountNameHashBits := api.ToBinary(txInfo.AccountNameHash, HashBitsSize)
	copy(pubData[currentOffset:currentOffset+HashBitsSize], accountNameHashBits)
	currentOffset += HashBitsSize

	for i := currentOffset; i < PubDataBitsSizePerTx; i++ {
		pubData[i] = 0
	}
	return pubData
}

func CollectPubDataFromFullExitNft(api API, txInfo FullExitNftTxConstraints) (pubData [PubDataBitsSizePerTx]Variable) {

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
	var paddingSize [112]Variable
	for i := 0; i < 112; i++ {
		paddingSize[i] = 0
	}
	ABits = append(paddingSize[:], ABits...)
	pubData[0] = api.FromBinary(ABits...)
	pubData[1] = txInfo.NftL1Address
	pubData[2] = txInfo.AccountNameHash
	pubData[3] = txInfo.CreatorAccountNameHash
	pubData[4] = txInfo.NftContentHash
	pubData[5] = txInfo.NftL1TokenId
	return pubData
}
