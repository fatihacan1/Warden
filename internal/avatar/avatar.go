// Package avatar validates and normalizes uploaded profile pictures.
//
// Uploaded bytes are never stored as-is. Every image is decoded and
// re-encoded as a 512x512 JPEG, which strips metadata (EXIF GPS location),
// defeats polyglot files (HTML/JS hidden in an image) and bounds storage.
package avatar

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	_ "image/gif" // register decoders
	"image/jpeg"
	_ "image/png"
	"runtime"

	"golang.org/x/image/draw"
	_ "golang.org/x/image/webp"
)

const (
	Size = 512
	// maxPixels rejects decompression bombs: a tiny PNG can declare a huge
	// canvas that would allocate gigabytes when decoded.
	maxPixels = 40_000_000
	maxSide   = 10_000
)

var (
	ErrUnsupported = errors.New("avatar: unsupported image format")
	ErrTooLarge    = errors.New("avatar: image dimensions too large")
	ErrBusy        = errors.New("avatar: processor busy")
)

// Processor bounds concurrent CPU heavy image work.
type Processor struct {
	slots chan struct{}
}

func NewProcessor() *Processor {
	return &Processor{slots: make(chan struct{}, max(1, runtime.GOMAXPROCS(0)/2))}
}

// Process returns a JPEG avatar.
func (p *Processor) Process(ctx context.Context, data []byte) ([]byte, error) {
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	case <-ctx.Done():
		return nil, ErrBusy
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, ErrUnsupported
	}
	switch format {
	case "jpeg", "png", "gif", "webp":
	default:
		return nil, ErrUnsupported
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > maxSide || cfg.Height > maxSide || cfg.Width*cfg.Height > maxPixels {
		return nil, ErrTooLarge
	}
	src, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, ErrUnsupported
	}
	return encode(cropSquare(src))
}

// cropSquare center-crops and scales to Size x Size on a white background
// (JPEG has no alpha channel).
func cropSquare(src image.Image) image.Image {
	b := src.Bounds()
	side := min(b.Dx(), b.Dy())
	x0 := b.Min.X + (b.Dx()-side)/2
	y0 := b.Min.Y + (b.Dy()-side)/2
	crop := image.Rect(x0, y0, x0+side, y0+side)

	dst := image.NewRGBA(image.Rect(0, 0, Size, Size))
	draw.Draw(dst, dst.Bounds(), &image.Uniform{C: color.White}, image.Point{}, draw.Src)
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, crop, draw.Over, nil)
	return dst
}

func encode(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 85}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
