# ART — Adaptive Radix Tree for DID Nonces

A production-ready, thread-safe Adaptive Radix Tree (ART) for `uint64` DID nonces with zstd wire encoding and optional disk-spill support.

## Overview

DID nonces are `uint64` values (nanosecond timestamp + random suffix). The ART indexes them with **O(8) lookup** — fixed depth of 8 bytes per `uint64`, completely independent of dataset size.

Four node types (`Node4 → Node16 → Node48 → Node256`) adapt to the actual child count, so memory usage scales with the data, not the key space.

### Performance (2.62M real nonces)

| Operation | Latency | Notes |
|-----------|---------|-------|
| Build (all nonces) | 225 ms | full insert of 2.62M keys |
| Single Insert | 13 ns | amortised |
| Contains (hit) | 21 ns | O(8) depth always |
| Contains (miss) | 21 ns | exits on first mismatch byte |
| Single Delete | 16 ns | node shrink included |
| Encode (zstd) | 61 ms | 19.96 MB → 12.64 MB (63% of raw) |
| Decode (zstd) | 145 ms | decompress + rebuild |
| Swap to disk | 90 ms | writes one zstd segment file |
| Cold load | 55 ms | first query after swap (disk read + decompress) |
| Warm load | 15 ns | subsequent queries (cached in memory) |
| Heap RAM | 136 MB | for 2.62M random uint64 nonces |

---

## Installation

```go
import "github.com/JupiterMetaLabs/JMDN_Merkletree/art"
```

---

## In-Memory ART

### Create and Insert

```go
a := art.New()

a.Insert(6424386505496921157)
a.Insert(17609362316754617524)
a.Insert(5815365071557427260)
```

Duplicate inserts are silently ignored.

### Contains

```go
if a.Contains(6424386505496921157) {
    fmt.Println("nonce exists")
}
```

### Delete

```go
deleted := a.Delete(6424386505496921157)
// deleted = true if the key was present, false if absent
```

Node types shrink automatically on delete (`Node256 → Node48 → Node16 → Node4`).
Single-child path nodes collapse to avoid dead tree branches.

### Merge two trees

```go
a := art.New()
b := art.New()

// populate both ...

a.Merge(b)   // inserts all keys from b into a; b is unchanged
```

### Iterate in sorted order

```go
a.Iter(func(nonce uint64) {
    fmt.Println(nonce)
})
```

`Iter` walks the tree in ascending key order.

### Other helpers

```go
a.Len()    // number of distinct keys
a.Keys()   // sorted []uint64 snapshot
a.Clear()  // remove all keys
```

---

## Wire Encoding (P2P Transport)

The codec is designed purely for sending an ART over a P2P connection. It never touches disk.

### How it works

```
ART walk → delta-encode keys → stream into zstd encoder → []byte
```

Instead of absolute keys, the encoder writes **sorted deltas** (difference between consecutive keys). For timestamp-based nonces the deltas are small, so zstd compresses them aggressively. No intermediate key slice is allocated — each 8-byte delta is streamed directly into the compressor.

### Encode (sender side)

```go
payload := art.Encode(a)
// send payload over your P2P connection
conn.Write(payload)
```

### Decode (receiver side)

```go
data, _ := io.ReadAll(conn)

received, err := art.Decode(data)
if err != nil {
    log.Fatal(err)
}
// received is a fully rebuilt *art.ART
```

### Size example

| Keys | Raw (8 B/key) | zstd encoded | Ratio |
|------|--------------|--------------|-------|
| 2.62M real nonces | 19.96 MB | 12.64 MB | 63% |
| 1000 sequential | 8 000 B | 45 B | 0.6% |

---

## Disk-Spill (SwappableART)

`SwappableART` wraps an ART with automatic disk-spill. When the in-memory key count reaches the threshold the hot ART is flushed to a zstd-compressed segment file and memory is freed. All operations continue to work transparently across hot and on-disk data.

### Create

```go
s, err := art.NewSwappable(
    "/var/lib/myapp/art-segments", // directory for segment files
    1_000_000,                      // spill threshold (keys in memory)
)
if err != nil {
    log.Fatal(err)
}
defer s.Close()
```

Use `art.DefaultThreshold` (1M keys ≈ 100 MB) if you are unsure.

### Insert

```go
err := s.Insert(nonce)
// If hot reaches the threshold this automatically writes a segment file
// and clears the hot ART.
```

### Contains

```go
found := s.Contains(nonce)
// Checks: tombstone → hot ART → each segment (min/max filter → binary search)
// Segment data is cached in memory after the first disk read.
```

### Delete

```go
s.Delete(nonce)
// Immediately removes from hot ART.
// On-disk segments are not rewritten; deleted keys are filtered on access
// via an in-memory tombstone set and cleaned up on the next Compact().
```

### Merge from another ART

```go
src := art.New()
// populate src ...

err := s.Merge(src)
```

### Force swap to disk now

```go
err := s.SwapToDisk()
// Writes current hot ART to a new segment file and clears hot.
// Use this before shutting down to persist in-memory data.
```

### Compact (merge all segments into one)

```go
err := s.Compact()
// Merges hot + all segment files into a single new segment.
// Applies tombstone deletions. Removes old segment files.
// Run periodically to keep the number of segments small.
```

### Iterate all live keys

```go
err := s.Iter(func(nonce uint64) {
    fmt.Println(nonce)
})
// Keys are not globally sorted across segment boundaries.
// Call Compact() first if sorted order is required.
```

### Monitoring

```go
s.Len()            // total live key count (hot + segments − tombstones)
s.SegmentCount()   // number of on-disk segments
```

---

## Segment files

Each segment file is a self-contained zstd-compressed binary blob:

```
uint64BE   key count
uint64BE × count   sorted delta-encoded keys
```

Files are named `seg-000000.art.zst`, `seg-000001.art.zst`, … in the configured directory. They are immutable once written; only `Compact()` removes old files.

---

## Concurrency

Both `ART` and `SwappableART` are safe for concurrent use. `ART` uses a `sync.RWMutex` (concurrent reads, exclusive writes). `SwappableART` uses a `sync.Mutex` around all operations.

---

## Architecture

```
art/
  art.go         Core ART: node types (Node4/16/48/256), Insert, Contains,
                 Delete, Merge, Iter, Keys, Clear. Thread-safe.

  codec.go       Wire transport only: Encode() and Decode().
                 Streaming zstd with delta encoding. No disk I/O.

  swappable.go   SwappableART: hot ART + on-disk zstd segments + tombstone set.
                 NewSwappable, Insert, Contains, Delete, Merge,
                 SwapToDisk, Compact, Iter, Len, Close.
```

---

## Reference

Leis et al., *"The Adaptive Radix Tree: ARTful Indexing for Main-Memory Databases"*, ICDE 2013.
