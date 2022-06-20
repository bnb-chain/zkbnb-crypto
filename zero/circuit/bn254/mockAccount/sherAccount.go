package mockAccount

import (
	curve "github.com/bnb-chain/zkbas-crypto/ecc/ztwistededwards/tebn254"
	"github.com/bnb-chain/zkbas-crypto/elgamal/twistededwards/tebn254/twistedElgamal"
	"math/big"
)

var (
	SherIndex         = uint32(3)
	SherName          = "sher.zecrey-legend"
	SherSk, _         = new(big.Int).SetString("1764340744225673614081856977301968708477688328010640838035450327471358028288", 10)
	SherPk, _         = curve.FromString("8Br57XNRstvIc4KUXNcDaRrk33rGsaY4em9js708FRg=")
	SherLockedAssetA  = uint64(100)
	SherAssetABalance = uint64(1000)
	SherCA, _         = twistedElgamal.FromString("EBAbkUxyhNR5OKdbfyDG5gFIen4e3GdF2Ha44xG0VaTf8qg+W7moJFSS/nlTtGSS4tlF6jQAB8F1e7Bq2SEEGg==")
	SherAssetBBalance = uint64(2000)
	SherCB, _         = twistedElgamal.FromString("sONa+/gZ16AKtc2IFnzzIeuLd5g+YhxzljHUmj4dfw/IfYb/de6RjsKC6IvabLdJ+Qf6oB6Go+Olaj7l4VPoLQ==")
	SherAssetCBalance = uint64(3000)
	SherCC, _         = twistedElgamal.FromString("ABH+DEKkMJavJmtmR++WhPbVbdZP7JHef1h2ZbB6n4ynt7CdMuF40v8HUav67L0BwHJV3uQLa8dlcS/+VS0JnA==")
	SherAssetDBalance = uint64(4000)
	SherCD, _         = twistedElgamal.FromString("3GyqFguiDxRmMlJs1aHMu9GmR8yRY5KESbCuIRJ5IgOZflBZOXukWasBZTeR1WU9z4qPvaYHq47SUTFoxhKJlg==")
	SherLpBalance     = uint64(10)
	SherCLp, _        = twistedElgamal.FromString("SsPrMFxlNWfbyVo52SQkj8+QRXwXiRKlXoOYED95FwjxVzELZXEvVJbGiB4fdvoPuETnu6DhbUEQTkfDHL3qhA==")
)
