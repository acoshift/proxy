package proxy

var tunnelIndex map[string]struct{}

func init() {
	list := loadList("tunnel")

	tunnelIndex = make(map[string]struct{})
	for _, x := range list {
		tunnelIndex[x] = struct{}{}
	}
}
