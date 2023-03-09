package signature

const (

	// SignatureTemplateWithdrawal Withdrawal ${amount} to: ${to.toLowerCase()}\nFee: ${fee} ${feeTokenAddress}\nNonce: ${nonce}
	SignatureTemplateWithdrawal = "Withdrawal %s to: %s\nFee: %s %d\nNonce: %d"
	// SignatureTemplateTransfer /* Transfer ${amount} ${tokenAddress} to: ${to.toLowerCase()}\nFee: ${fee} ${feeTokenAddress}\nNonce: ${nonce} */
	SignatureTemplateTransfer = "Transfer %s %d to: %d\nFee: %s %d\nNonce: %d"
	// SignatureTemplateCreateCollection CreateCollection ${accountIndex} ${collectionName} \nFee: ${fee} ${feeTokenAddress}\nNonce: ${nonce}
	SignatureTemplateCreateCollection = "CreateCollection %d %s \nFee: %s %d\nNonce: %d"
	// SignatureTemplateMintNft MintNFT ${contentHash} for: ${recipient.toLowerCase()}\nFee: ${fee} ${feeTokenAddress}\nNonce: ${nonce}
	SignatureTemplateMintNft = "MintNFT %s for: %d\nFee: %s %d\nNonce: %d"
	// SignatureTemplateTransferNft TransferNFT ${NftIndex} ${fromAccountIndex} to ${toAccountIndex} \nFee: ${fee} ${feeTokenAddress}\nNonce: ${nonce}
	SignatureTemplateTransferNft = "TransferNFT %d %d to %d \nFee: %s %d\nNonce: %d"
	// SignatureTemplateWithdrawalNft Withdrawal ${tokenIndex} to: ${to.toLowerCase()}\nFee: ${fee} ${feeTokenAddress}\nNonce: ${nonce}
	SignatureTemplateWithdrawalNft = "Withdrawal %d to: %s\nFee: %s %d\nNonce: %d"
	// SignatureTemplateCancelOffer CancelOffer ${offerId} by: ${accountIndex} \nFee: ${fee} ${feeTokenAddress}\nNonce: ${nonce}
	SignatureTemplateCancelOffer = "CancelOffer %d by: %d \nFee: %s %d\nNonce: %d"
	// SignatureTemplateAtomicMatch AtomicMatch ${amount} ${offerId} ${nftIndex} ${accountIndex} \nFee: ${fee} ${feeTokenAddress}\nNonce: ${nonce}
	SignatureTemplateAtomicMatch = "AtomicMatch %s %d %d %d \nFee: %s %d\nNonce: %d"
	// SignatureTemplateAccount AccountIndex:{AccountIndex}\nNftIndex:{NftIndex}\nNonce:{Nonce}
	SignatureTemplateUpdateNFT = "AccountIndex:%d\nNftIndex:%d\nNonce:%d"
)
