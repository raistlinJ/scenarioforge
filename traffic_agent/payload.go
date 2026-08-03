package main

import (
	"math/rand"
	"strings"
)

// Content types shape the bytes on the wire so a capture looks like the kind of
// traffic the scenario describes. These are synthetic patterns, not real media:
// the goal is recognizable framing (JPEG markers, H.264 start codes) at a
// controlled rate, matching what the previous Python senders emitted.
const (
	ContentText      = "text"
	ContentPhoto     = "photo"
	ContentAudio     = "audio"
	ContentVideo     = "video"
	ContentGibberish = "gibberish"
)

var httpLikeLine = []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: core-traffic\r\n\r\n")

// randomContentTypes mirrors the weighted choice the Python sender made when
// content_type was "random": text and gibberish twice as likely as the rest.
var randomContentTypes = []struct {
	name   string
	weight int
}{
	{ContentText, 2},
	{ContentPhoto, 1},
	{ContentAudio, 1},
	{ContentVideo, 1},
	{ContentGibberish, 2},
}

// NormalizeContentType maps the aliases accepted in scenario XML onto the
// canonical names. "random"/"" resolves per agent start, like the old scripts
// did per script start, so a single flow definition still varies between runs.
func NormalizeContentType(raw string, rng *rand.Rand) string {
	name := strings.ToLower(strings.TrimSpace(raw))
	switch name {
	case "", "random":
		total := 0
		for _, entry := range randomContentTypes {
			total += entry.weight
		}
		pick := rng.Intn(total)
		for _, entry := range randomContentTypes {
			pick -= entry.weight
			if pick < 0 {
				return entry.name
			}
		}
		return ContentGibberish
	case "text", "txt", "log":
		return ContentText
	case "photo", "image", "jpeg", "jpg", "png":
		return ContentPhoto
	case "audio", "mp3", "aac":
		return ContentAudio
	case "video", "h264", "mp4":
		return ContentVideo
	case "gibberish", "bytes", "junk", "rand", "random-bytes":
		return ContentGibberish
	default:
		return ContentGibberish
	}
}

// PayloadBuilder produces payloads of a requested size for one content type.
// An audio frame is generated once and reused, matching the original behavior
// and avoiding a fresh 1 KiB of randomness on every tick.
type PayloadBuilder struct {
	contentType string
	rng         *rand.Rand
	audioFrame  []byte
}

func NewPayloadBuilder(contentType string, rng *rand.Rand) *PayloadBuilder {
	b := &PayloadBuilder{contentType: contentType, rng: rng}
	if contentType == ContentAudio {
		b.audioFrame = make([]byte, 1024)
		b.rng.Read(b.audioFrame)
	}
	return b
}

// Bytes returns a payload of exactly n bytes (n <= 0 yields an empty slice).
func (b *PayloadBuilder) Bytes(n int) []byte {
	if n <= 0 {
		return nil
	}
	switch b.contentType {
	case ContentText:
		out := make([]byte, 0, n)
		for len(out) < n {
			out = append(out, httpLikeLine...)
		}
		return out[:n]

	case ContentPhoto:
		// JPEG-like: SOI marker, 0xFF-interleaved body, EOI marker.
		out := make([]byte, 0, n+2)
		out = append(out, 0xff, 0xd8)
		limit := n - 2
		if limit < 4 {
			limit = 4
		}
		for len(out) < limit {
			out = append(out, 0xff, byte(b.rng.Intn(0xff)))
		}
		out = append(out, 0xff, 0xd9)
		if len(out) > n {
			return out[:n]
		}
		return out

	case ContentAudio:
		out := make([]byte, 0, n+len(b.audioFrame))
		for len(out) < n {
			out = append(out, b.audioFrame...)
		}
		return out[:n]

	case ContentVideo:
		// NAL-like segments, each prefixed with the 0x000001 start code.
		chunk := n / 4
		if chunk < 256 {
			chunk = 256
		}
		if chunk > 8192 {
			chunk = 8192
		}
		out := make([]byte, 0, n+4)
		for len(out) < n {
			out = append(out, 0x00, 0x00, 0x01)
			remaining := n - len(out)
			if remaining <= 0 {
				break
			}
			size := chunk
			if size > remaining {
				size = remaining
			}
			blob := make([]byte, size)
			b.rng.Read(blob)
			out = append(out, blob...)
		}
		return out[:n]

	default: // gibberish and anything unrecognized
		out := make([]byte, n)
		b.rng.Read(out)
		return out
	}
}
