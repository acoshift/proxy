package proxy

var tunnelList = []string{
	// gcloud
	"www.googleapis.com",
	"accounts.google.com",

	// ios
	"*.mzstatic.com",
	"*.icloud.com",
	"*.adobess.com",
	"*.apple.com",

	// apps
	"api.twitter.com",
	"paypal.com", "*.paypal.com",
	"kasikornbank.com", "*.kasikornbank.com", "kasikornbankpubliccompany.sc.omtrdc.net",
	"api.mangarockhd.com",
}

var tunnelIndex map[string]struct{}

func init() {
	tunnelIndex = make(map[string]struct{})
	for _, x := range tunnelList {
		tunnelIndex[x] = struct{}{}
	}
}
