package main

import (
	"bytes"
	"math/rand"
	"testing"
)

func newRNG() *rand.Rand { return rand.New(rand.NewSource(42)) }

func TestPayloadSizesAreExact(t *testing.T) {
	for _, content := range []string{ContentText, ContentPhoto, ContentAudio, ContentVideo, ContentGibberish} {
		builder := NewPayloadBuilder(content, newRNG())
		for _, size := range []int{1, 2, 7, 64, 1023, 1024, 4096, 9000} {
			got := builder.Bytes(size)
			if len(got) != size {
				t.Fatalf("%s: asked for %d bytes, got %d", content, size, len(got))
			}
		}
	}
}

func TestPayloadNonPositiveSizeIsEmpty(t *testing.T) {
	builder := NewPayloadBuilder(ContentGibberish, newRNG())
	for _, size := range []int{0, -1, -100} {
		if got := builder.Bytes(size); len(got) != 0 {
			t.Fatalf("size %d should produce no bytes, got %d", size, len(got))
		}
	}
}

func TestTextPayloadLooksLikeHTTP(t *testing.T) {
	builder := NewPayloadBuilder(ContentText, newRNG())
	got := builder.Bytes(len(httpLikeLine) * 2)
	if !bytes.HasPrefix(got, []byte("GET /index.html HTTP/1.1\r\n")) {
		t.Fatalf("text payload should start with an HTTP request line, got %q", got[:24])
	}
}

func TestPhotoPayloadCarriesJPEGMarkers(t *testing.T) {
	builder := NewPayloadBuilder(ContentPhoto, newRNG())
	got := builder.Bytes(512)
	if !bytes.HasPrefix(got, []byte{0xff, 0xd8}) {
		t.Fatalf("photo payload should start with the JPEG SOI marker")
	}
	// A capture should show JPEG-like framing rather than uniform random bytes.
	if !bytes.Contains(got, []byte{0xff}) {
		t.Fatalf("photo payload should contain 0xff marker bytes")
	}
}

func TestVideoPayloadCarriesNALStartCodes(t *testing.T) {
	builder := NewPayloadBuilder(ContentVideo, newRNG())
	got := builder.Bytes(4096)
	if !bytes.HasPrefix(got, []byte{0x00, 0x00, 0x01}) {
		t.Fatalf("video payload should start with an H.264 start code")
	}
}

func TestAudioFrameIsReusedNotRegenerated(t *testing.T) {
	builder := NewPayloadBuilder(ContentAudio, newRNG())
	got := builder.Bytes(2048)
	if !bytes.Equal(got[:1024], got[1024:2048]) {
		t.Fatalf("audio payload should repeat a single 1KiB frame")
	}
}

func TestContentTypeAliases(t *testing.T) {
	cases := map[string]string{
		"txt": ContentText, "log": ContentText, "TEXT": ContentText,
		"image": ContentPhoto, "jpeg": ContentPhoto, "png": ContentPhoto,
		"mp3": ContentAudio, "aac": ContentAudio,
		"h264": ContentVideo, "mp4": ContentVideo,
		"junk": ContentGibberish, "bytes": ContentGibberish,
	}
	for input, want := range cases {
		if got := NormalizeContentType(input, newRNG()); got != want {
			t.Fatalf("NormalizeContentType(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRandomContentTypeResolvesToAKnownType(t *testing.T) {
	valid := map[string]bool{
		ContentText: true, ContentPhoto: true, ContentAudio: true,
		ContentVideo: true, ContentGibberish: true,
	}
	for _, input := range []string{"", "random", "RANDOM"} {
		got := NormalizeContentType(input, newRNG())
		if !valid[got] {
			t.Fatalf("NormalizeContentType(%q) produced unknown type %q", input, got)
		}
	}
}

func TestSameSeedProducesSamePayload(t *testing.T) {
	// Reproducibility matters: the scenario pipeline threads one seed through
	// every phase, and traffic should not be the exception.
	a := NewPayloadBuilder(ContentGibberish, rand.New(rand.NewSource(7))).Bytes(256)
	b := NewPayloadBuilder(ContentGibberish, rand.New(rand.NewSource(7))).Bytes(256)
	if !bytes.Equal(a, b) {
		t.Fatalf("identical seeds should produce identical payloads")
	}
	c := NewPayloadBuilder(ContentGibberish, rand.New(rand.NewSource(8))).Bytes(256)
	if bytes.Equal(a, c) {
		t.Fatalf("different seeds should produce different payloads")
	}
}
