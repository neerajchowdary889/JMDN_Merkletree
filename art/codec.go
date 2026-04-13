package art

// codec.go — wire transport codec for sending an ART over a P2P connection.
//
// Only two public functions exist: Encode (before sending) and Decode (on receive).
// Compression is zstd; it is never used for disk storage.
//
// # Memory model
//
// The old approach needed three full-size buffers simultaneously:
//
//	Keys() → []uint64        n × 8 B   (all keys materialised)
//	→ raw    []byte          n × 8 B   (byte view of the same data)
//	→ zstd output                      (compressed result)
//
// The new approach streams directly from the tree walk into the zstd encoder.
// No intermediate key slice is ever allocated; a single reused 8-byte buffer
// is the only per-key allocation:
//
//	ART walk → 8-byte delta → zstd encoder → output
//
// # Delta encoding
//
// Instead of writing absolute keys we write sorted deltas:
//
//	wire[0]   = key[0]              (first key as-is)
//	wire[i]   = key[i] - key[i-1]  (difference between consecutive sorted keys)
//
// ART.Iter delivers keys in ascending order, so all deltas are ≥ 0.
// For timestamp-based DID nonces (close together in value) deltas are tiny
// and zstd compresses them far below 8 bytes each.  For random keys the
// memory saving from streaming still applies even if the ratio is modest.
//
// # Wire format (inside the zstd frame)
//
//	[4]byte   "ART\x02"   magic + version
//	uint64BE  n           number of keys
//	uint64BE × n          deltas in sorted order

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// ─── encoder pool ─────────────────────────────────────────────────────────────
//
// zstd.Encoder is not safe for concurrent streaming use, so we keep a pool.
// Each encoder is reset to a new output writer before use and returned after.

var encoderPool = sync.Pool{
	// Time: O(1) — constructs one encoder (pool miss only).
	New: func() any {
		// Default is SpeedDefault (3) which is a good compromise between speed and compression ratio.
		// SpeedBestCompression (10) is the highest compression ratio but is also the slowest.
		e, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
		// e, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
		return e
	},
}

// sharedDecoder is a singleton; zstd.Decoder.DecodeAll is concurrency-safe.
var (
	decOnce    sync.Once
	sharedDec  *zstd.Decoder
)

// Time: O(1) — reader is created once under sync.Once, then this only returns the pointer.
func getDecoder() *zstd.Decoder {
	decOnce.Do(func() { sharedDec, _ = zstd.NewReader(nil) })
	return sharedDec
}

// ─── Encode ──────────────────────────────────────────────────────────────────

// Encode compresses the ART into a compact byte slice ready to send over a
// P2P connection.
//
// The tree is walked in ascending order; keys are delta-encoded and streamed
// directly into the zstd encoder — no intermediate key slice is allocated.
//
// Time: O(n) where n = a.Len() — one ascending walk over n keys and zstd work
// linear in the uncompressed payload size O(n) bytes (12-byte header + 8n deltas).
func Encode(a *ART) []byte {
	n := a.Len()

	var out bytes.Buffer
	out.Grow(12 + n*8/8) // rough starting capacity (~10-12% of raw for typical nonces)

	enc := encoderPool.Get().(*zstd.Encoder)
	enc.Reset(&out)

	// Header: magic + key count.
	var hdr [12]byte
	copy(hdr[:4], "ART\x02")
	binary.BigEndian.PutUint64(hdr[4:], uint64(n))
	enc.Write(hdr[:]) //nolint:errcheck – in-memory write cannot fail

	// Stream delta-encoded keys directly from the tree walk.
	// One stack-allocated 8-byte buffer is reused for every key.
	var prev uint64
	var kbuf [8]byte
	a.Iter(func(k uint64) {
		binary.BigEndian.PutUint64(kbuf[:], k-prev) // delta ≥ 0 (walk is ascending)
		prev = k
		enc.Write(kbuf[:]) //nolint:errcheck
	})

	enc.Close()            //nolint:errcheck
	encoderPool.Put(enc)

	return out.Bytes()
}

// ─── Decode ──────────────────────────────────────────────────────────────────

// Decode reconstructs an ART from a payload produced by Encode.
// Returns an error if the payload is malformed or corrupted.
//
// Time: O(n) where n is the key count in the payload — zstd decompression is
// linear in compressed input size and produces O(n) bytes; rebuilding the ART
// is n Insert calls on 64-bit keys (fixed trie depth), O(n) total.
func Decode(data []byte) (*ART, error) {
	raw, err := getDecoder().DecodeAll(data, nil)
	if err != nil {
		return nil, fmt.Errorf("art decode: zstd: %w", err)
	}
	if len(raw) < 12 {
		return nil, fmt.Errorf("art decode: payload too short (%d bytes)", len(raw))
	}
	if string(raw[:4]) != "ART\x02" {
		return nil, fmt.Errorf("art decode: unknown magic %x (expected ART\\x02)", raw[:4])
	}
	count := int(binary.BigEndian.Uint64(raw[4:]))
	if len(raw) < 12+count*8 {
		return nil, fmt.Errorf("art decode: truncated (need %d bytes, got %d)", 12+count*8, len(raw))
	}

	a := New()
	var cur uint64
	for i := range count {
		cur += binary.BigEndian.Uint64(raw[12+i*8:]) // accumulate deltas → absolute key
		a.Insert(cur)
	}
	return a, nil
}
