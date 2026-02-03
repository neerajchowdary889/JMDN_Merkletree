package merkletree

import (
	"fmt"
)

// Bisect finds the first chunk (range of size <= BlockMerge) that differs
// between this Builder (b) and another Builder (other).
//
// Efficiency:
//   - Traverses the in-memory tree nodes O(log N).
//   - No re-hashing required.
func (b *Builder) Bisect(other *Builder) (start uint64, count uint32, err error) {
	// 1. Compare Peaks (MMR Scan)
	peaks1 := b.outer.peaks
	peaks2 := other.outer.peaks

	maxLevel := len(peaks1)
	if len(peaks2) > maxLevel {
		maxLevel = len(peaks2)
	}

	for i := maxLevel - 1; i >= 0; i-- {
		var p1, p2 *Node
		if i < len(peaks1) {
			p1 = peaks1[i]
		}
		if i < len(peaks2) {
			p2 = peaks2[i]
		}

		if p1 == nil && p2 == nil {
			continue
		}

		if p1 == nil || p2 == nil {
			if p1 != nil {
				return p1.Metadata.Start, p1.Metadata.Count, nil
			}
			return p2.Metadata.Start, p2.Metadata.Count, nil
		}

		// Content mismatch?
		if p1.Root != p2.Root {
			fmt.Printf("Bisecting Peak Level %d (Range %d..%d)\n", i, p1.Metadata.Start, p1.Metadata.Start+uint64(p1.Metadata.Count)-1)
			return b.bisectRecursive(p1, p2)
		}
	}

	// 2. Compare Partial Buffer
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

func (b *Builder) bisectRecursive(n1, n2 *Node) (uint64, uint32, error) {
	// Base Case: Leaf Node (Chunk)
	// If HasData or if we are at the bottom (no children but matching count).
	if n1.HasData || n1.Left == nil {
		return n1.Metadata.Start, n1.Metadata.Count, nil
	}

	// Ensure n2 matches structure. If n2 is somehow different structure, returns mismatch.
	if n2.Left == nil {
		// Structure mismatch at this level? return this range.
		return n1.Metadata.Start, n1.Metadata.Count, nil
	}

	// Check Left Child First
	left1 := n1.Left
	left2 := n2.Left

	if left1.Root != left2.Root {
		fmt.Printf(" -> Going Left ([%d..%d])\n", left1.Metadata.Start, left1.Metadata.Start+uint64(left1.Metadata.Count)-1)
		return b.bisectRecursive(left1, left2)
	}

	// Else go Right
	// If Right is nil? (Should not happen in perfect binary tree logic, but check)
	if n1.Right == nil || n2.Right == nil {
		// Should not happen if parents matched up to here and Left matched.
		return n1.Metadata.Start, n1.Metadata.Count, nil
	}

	right1 := n1.Right
	// right2 := n2.Right

	fmt.Printf(" -> Going Right ([%d..%d])\n", right1.Metadata.Start, right1.Metadata.Start+uint64(right1.Metadata.Count)-1)
	return b.bisectRecursive(n1.Right, n2.Right) // Use explicit right child
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
