package zecrey

import "zecrey-crypto/rangeProofs/twistededwards/tebn254/bulletProofs"

func Setup(N, M int64) (*ZSetupParams, error) {
	bpSetupParams, err := bulletProofs.Setup(N, M)
	if err != nil {
		return nil, err
	}
	return &ZSetupParams{bpSetupParams}, nil
}
