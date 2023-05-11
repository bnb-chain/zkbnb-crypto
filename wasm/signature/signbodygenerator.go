package signature

const (
	TemplateWithdrawal = "Withdrawal \nwithdrawal amount: %s %s \nto account address: %s \ngas fee amount: %s BNB \nnonce: %d"

	TemplateTransfer = "Transfer \ntransfer amount: %s %s \nto account address: %s \ngas fee amount: %s BNB \nnonce: %d"

	TemplateCreateCollection = "CreateCollection \ncreate collection name: %s \ngas fee amount: %s BNB \nnonce: %d"

	TemplateMintNft = "MintNFT \nto account address: %s \ngas fee amount: %s BNB \nnonce: %d"

	TemplateTransferNft = "TransferNFT \nnft name: %s \nto account address: %s \ngas fee amount: %s BNB \nnonce: %d"

	TemplateWithdrawalNft = "WithdrawalNFT \nnft name: %s \nto account address: %s \ngas fee amount: %s BNB \nnonce: %d"

	TemplateCancelOffer = "CancelOffer \nnft name: %s \ngas fee amount: %s BNB \nnonce: %d"

	TemplateUpdateNFT = "NFT Update \naccount index: %d \nnft index: %d \nnonce: %d"

	TemplateChangePubKey = "Register zkBNB Account\n\npubkeyX: 0x%s\npubkeyY: 0x%s\nnonce: %s\naccount index: %s\n\nOnly sign this message for a trusted client!"

	TemplateOffer = "NFT Offer \nnft name: %s \nnft asset amount:%s %s"
)
