package signature

const (
	TemplateWithdrawal = "Withdrawal \nwithdrawal amount: %s \nto account address: %s \ngas fee asset: %d \ngas fee amount: %s \nnonce: %d"

	TemplateTransfer = "Transfer \ntransfer amount: %s \nfrom account index: %d \nto account address: %s \ngas fee asset: %d \ngas fee amount: %s \nnonce: %d"

	TemplateCreateCollection = "CreateCollection \ncreate account index: %d \ncreate collection name: %s \ngas fee asset: %d \ngas fee amount: %s \nnonce: %d"

	TemplateMintNft = "MintNFT \nto account address: %s \ngas fee asset: %d \ngas fee amount: %s \nnonce: %d"

	TemplateTransferNft = "TransferNFT \nnft index: %d \nfrom account index: %d \nto account address: %s \ngas fee asset: %d \ngas fee amount: %s \nnonce: %d"

	TemplateWithdrawalNft = "WithdrawalNFT \nnft index: %d \nto account address: %s \ngas fee asset: %d \ngas fee amount: %s \nnonce: %d"

	TemplateCancelOffer = "CancelOffer \nnft index: %d \ncancel account index: %d \ngas fee asset: %d \ngas fee amount: %s \nnonce: %d"

	TemplateUpdateNFT = "Update NFT \naccount index: %d \nnft index: %d \nnonce: %d"

	TemplateChangePubKey = "Register zkBNB Account\n\npubkeyX: 0x%s\npubkeyY: 0x%s\nnonce: %s\naccount index: %s\n\nOnly sign this message for a trusted client!"

	TemplateOffer = "Offer NFT Tx \naccount index: %d \nnft index: %d \nnft asset: %d \nnft asset amount:%s"
)
