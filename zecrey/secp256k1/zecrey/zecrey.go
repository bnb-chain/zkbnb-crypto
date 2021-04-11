package zecrey

import (
	"Zecrey-crypto/rangeProofs/secp256k1/bulletProofs"
)

func Setup(b int64) (*BulletProofSetupParams, error) {
	return bulletProofs.Setup(b)
}

func ProveTransfer(statement *ZKSneakTransferStatement, params *BulletProofSetupParams) (proof *ZKSneakTransferProof, err error) {
	proof = new(ZKSneakTransferProof)
	proof.ProveAnonEnc(statement.Relations)
	proof.ProveAnonRange(statement, params)
	proof.ProveEqual(statement.Relations)
	return proof, nil
}

func (proof *ZKSneakTransferProof) Verify() bool {
	return proof.VerifyAnonEnc() && proof.VerifyAnonRange() && proof.VerifyEqual()
}
