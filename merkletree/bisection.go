package merkletree

import (
	"fmt"
)

// Bisect finds the first chunk (range of size <= BlockMerge) that differs
// between this Builder (b) and another Builder (other).
// It requires the full raw data (localHashes, remoteHashes) to recompute
// sub-roots during the descent, as the Builder only stores Peaks.
//
// Arguments:
//   - other: The remote builder state to compare against.
//   - localHashes: The raw data backing 'b'.
//   - remoteHashes: The raw data backing 'other'.
//
// Efficiency:
//   - Compares existing peaks O(1).
//   - Only re-hashes the specific path down to the mismatch O(log N * BlockMerge).
func (b *Builder) Bisect(other *Builder, localHashes []Hash32, remoteHashes []Hash32) (start uint64, count uint32, err error) {
	// 1. Compare Peaks (MMR Scan)
	// We scan from highest level (largest range) to lowest.
	// This corresponds to a Left-to-Right scan in terms of range coverage.

	peaks1 := b.outer.peaks
	peaks2 := other.outer.peaks

	maxLevel := len(peaks1)
	if len(peaks2) > maxLevel {
		maxLevel = len(peaks2)
	}

	for i := maxLevel - 1; i >= 0; i-- {
		var p1, p2 *node
		if i < len(peaks1) {
			p1 = peaks1[i]
		}
		if i < len(peaks2) {
			p2 = peaks2[i]
		}

		if p1 == nil && p2 == nil {
			continue
		}

		// Structural mismatch?
		if p1 == nil || p2 == nil {
			if p1 != nil {
				return p1.start, p1.count, nil
			}
			return p2.start, p2.count, nil
		}

		// Content mismatch?
		if p1.sum != p2.sum {
			fmt.Printf("Bisecting Peak Level %d (Range %d..%d)\n", i, p1.start, p1.start+uint64(p1.count)-1)
			return b.bisectRecursive(localHashes, remoteHashes, p1.start, p1.count)
		}
	}

	// 2. Compare Partial Buffer (if no peak mismatch)
	// Peaks only cover committed chunks.
	if len(b.inChunkElems) != len(other.inChunkElems) {
		return b.inChunkStart, uint32(min(len(b.inChunkElems), len(other.inChunkElems))), nil
	}
	for i := range b.inChunkElems {
		if b.inChunkElems[i] != other.inChunkElems[i] {
			return b.inChunkStart, uint32(len(b.inChunkElems)), nil
		}
	}

	return 0, 0, nil // No difference
}

func (b *Builder) bisectRecursive(local, remote []Hash32, start uint64, count uint32) (uint64, uint32, error) {
	// Base Case: Single Chunk?
	if count <= uint32(b.cfg.BlockMerge) {
		return start, count, nil
	}

	// Recursive Step: Split Range
	// Peaks in this MMR implementation are strictly Perfect Binary Trees (size 2^k chunks).
	// So we can split perfectly in half.
	leftCount := count / 2
	rightCount := count - leftCount

	// Check Left Child First
	// Range: [start, start + leftCount - 1]

	// Optimization: Use lightweight recursive hasher instead of full Builder
	leftHashLocal := b.computeSubtreeRoot(local, start, leftCount)
	leftHashRemote := b.computeSubtreeRoot(remote, start, leftCount)

	if leftHashLocal != leftHashRemote {
		fmt.Printf(" -> Going Left ([%d..%d])\n", start, start+uint64(leftCount)-1)
		return b.bisectRecursive(local, remote, start, leftCount)
	}

	// Else go Right
	fmt.Printf(" -> Going Right ([%d..%d])\n", start+uint64(leftCount), start+uint64(count)-1)
	return b.bisectRecursive(local, remote, start+uint64(leftCount), rightCount)
}

// computeSubtreeRoot calculates the root of a Perfect Binary Tree covering `count` blocks
// without allocating a new Builder.
// Precondition: count is a multiple of BlockMerge * 2^k (or just > BlockMerge for inner nodes).
func (b *Builder) computeSubtreeRoot(fullData []Hash32, start uint64, count uint32) Hash32 {
	// Base Case: Leaf (Chunk)
	if count <= uint32(b.cfg.BlockMerge) {
		subset := fullData[start : start+uint64(count)]
		return ComputeChunkDigest(b.cfg.HashFactory, start, subset)
	}

	// Recursive Step: Inner Node
	// Split in half
	leftCount := count / 2
	rightCount := count - leftCount

	left := b.computeSubtreeRoot(fullData, start, leftCount)
	right := b.computeSubtreeRoot(fullData, start+uint64(leftCount), rightCount)

	return outerNodeDigest(b.cfg.HashFactory, start, count, left, right)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
