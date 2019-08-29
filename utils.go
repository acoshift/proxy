package proxy

import (
	"io/ioutil"
	"strings"
)

func loadList(filename string) []string {
	bs, _ := ioutil.ReadFile(filename)

	var xs []string
	for _, x := range strings.Split(string(bs), "\n") {
		x = strings.TrimSpace(x)
		if x == "" || strings.HasPrefix(x, "#") {
			continue
		}
		xs = append(xs, x)
	}
	return xs
}
