package avatar

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"
)

func pngBytes(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for x := range w {
		img.Set(x, h/2, color.NRGBA{R: 255, A: 255})
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestProcessProducesSquareJPEG(t *testing.T) {
	p := NewProcessor()
	out, err := p.Process(context.Background(), pngBytes(t, 800, 300))
	if err != nil {
		t.Fatal(err)
	}
	img, err := jpeg.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("output is not a JPEG: %v", err)
	}
	if b := img.Bounds(); b.Dx() != Size || b.Dy() != Size {
		t.Fatalf("got %v", b)
	}
}

func TestRejectsNonImages(t *testing.T) {
	p := NewProcessor()
	for _, data := range [][]byte{
		[]byte("<html><script>alert(1)</script></html>"),
		[]byte("%PDF-1.7"),
		{},
	} {
		if _, err := p.Process(context.Background(), data); !errors.Is(err, ErrUnsupported) {
			t.Errorf("expected ErrUnsupported, got %v", err)
		}
	}
}

// A PNG header that declares a 100000x100000 canvas: decoding it would
// allocate ~40 GB. It must be rejected from the header alone.
func TestRejectsDecompressionBomb(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte("\x89PNG\r\n\x1a\n"))
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], 100000)
	binary.BigEndian.PutUint32(ihdr[4:], 100000)
	ihdr[8], ihdr[9] = 8, 6 // 8-bit RGBA
	chunk := append([]byte("IHDR"), ihdr...)
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(ihdr)))
	buf.Write(chunk)
	_ = binary.Write(&buf, binary.BigEndian, crc32.ChecksumIEEE(chunk))

	if _, err := NewProcessor().Process(context.Background(), buf.Bytes()); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
}
