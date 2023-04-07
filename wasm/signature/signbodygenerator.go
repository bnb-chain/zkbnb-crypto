package signature

const (

	// SignatureTemplateWithdrawal /* Withdrawal ${amount} to: ${to.toLowerCase()}\nFee: ${fee} ${feeTokenAddress}\nNonce: ${nonce} */
	SignatureTemplateWithdrawal = "Withdrawal %s to: %s\nFee: %s %d\nNonce: %d"
	// SignatureTemplateTransfer /* Transfer ${amount} ${tokenAddress} to: ${toAddress}\nFee: ${fee} ${feeTokenAddress}\nNonce: ${nonce} */
	SignatureTemplateTransfer = "Transfer %s %d to: %s\nFee: %s %d\nNonce: %d"
	// SignatureTemplateCreateCollection /* CreateCollection ${accountIndex} ${collectionName} \nFee: ${fee} ${feeTokenAddress}\nNonce: ${nonce} */
	SignatureTemplateCreateCollection = "CreateCollection %d %s \nFee: %s %d\nNonce: %d"
	// SignatureTemplateMintNft /* MintNFT ${contentHash} for: ${recipient.toLowerCase()}\nFee: ${fee} ${feeTokenAddress}\nNonce: ${nonce} */
	SignatureTemplateMintNft = "MintNFT %s for: %d\nFee: %s %d\nNonce: %d"
	// SignatureTemplateTransferNft /* TransferNFT ${NftIndex} ${fromAccountIndex} to ${toAddress} \nFee: ${fee} ${feeTokenAddress}\nNonce: ${nonce} */
	SignatureTemplateTransferNft = "TransferNFT %d %d to %s \nFee: %s %d\nNonce: %d"
	// SignatureTemplateWithdrawalNft /* Withdrawal ${tokenIndex} to: ${to.toLowerCase()}\nFee: ${fee} ${feeTokenAddress}\nNonce: ${nonce} */
	SignatureTemplateWithdrawalNft = "Withdrawal %d to: %s\nFee: %s %d\nNonce: %d"
	// SignatureTemplateCancelOffer /* CancelOffer ${offerId} by: ${accountIndex} \nFee: ${fee} ${feeTokenAddress}\nNonce: ${nonce} */
	SignatureTemplateCancelOffer = "CancelOffer %d by: %d \nFee: %s %d\nNonce: %d"
	// SignatureTemplateUpdateNFT /* AccountIndex:{AccountIndex}\nNftIndex:{NftIndex}\nNonce:{Nonce} */
	SignatureTemplateUpdateNFT = "Update NFT \nAccountIndex: %d\nNftIndex: %d\nNonce: %d"
	// SignatureTemplateChangePubKey /* Change Public Key \nPubKeyX:${pubKeyX} \nPubKeyY:${pubKeyY} \nAccountIndex:${accountIndex} \nNonce: ${nonce} */
	SignatureTemplateChangePubKey = "Register zkBNB Account\n\npubkeyX: 0x%s\npubkeyY: 0x%s\nnonce: %s\naccount index: %s\n\nOnly sign this message for a trusted client!"
	// SignatureTemplateOffer /* Offer NFT Tx \nAccountIndex:${accountIndex} \nNftIndex:${nftIndex} \nAssetId:${assetId} \nAssetAmount: ${assetAmount} */
	SignatureTemplateOffer = "Offer NFT Tx \nAccountIndex:%d \nNftIndex:%d \nAssetId:%d \nAssetAmount:%s"
)
