package zecrey

import (
	"zecrey-crypto/rangeProofs/secp256k1/bulletProofs"
)

func Setup(b int64, m int64) (*TransferParams, error) {
	params, err := bulletProofs.Setup(b, m)
	return &TransferParams{params}, err
}

func ProveTransfer(statement *TransferProofStatement, params *BulletProofSetupParams) (proof *ZKSneakTransferProof, err error) {
	proof = new(ZKSneakTransferProof)
	proof.ProveAnonEnc(statement.Relations)
	proof.ProveAnonRange(statement, params)
	proof.ProveEqual(statement.Relations)
	return proof, nil
}

func (proof *ZKSneakTransferProof) Verify() bool {
	return proof.VerifyAnonEnc() && proof.VerifyAnonRange() && proof.VerifyEqual()
}
