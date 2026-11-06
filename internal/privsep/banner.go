package privsep

import (
	"io"
	"os"
)

const maxBannerSize = 64 * 1024

func loadBanner(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBannerSize+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxBannerSize {
		data = data[:maxBannerSize]
	}
	return string(data), nil
}
