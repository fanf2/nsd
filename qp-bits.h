/*
 * qp-trie - a DNS-specific quelques-bits popcount trie for NSD
 *
 * Internal definitions shared by the implementation and test harness.
 *
 * Written by Tony Finch <dot@dotat.at>
 * See LICENSE for the license.
 */
#ifndef QP_BITS_H
#define QP_BITS_H

/*
 * A bit of the right type
 */
#define W1 ((qp_word)1)

/*
 * Type of the number of bits set in a word (as in Hamming weight or
 * popcount) which is used for the position of a node in the sparse
 * vector of twigs.
 */
typedef uint8_t qp_weight;

/*
 * Type of the number of a bit inside a word (0..63).
 */
typedef uint8_t qp_shift;

/*
 * Type of a trie lookup key.
 *
 * A lookup key is an array of bit numbers. A domain name can be up to
 * 255 bytes. When converted to a key, each byte in the name
 * corresponds to one bit number in the key if it is a common
 * character, or it is expanded to two bit numbers in the key when the
 * byte isn't a common character. So we allow keys to be up to 512
 * bytes. (The actual max is a few smaller than that.)
 *
 * A key is ephemeral, allocated on the stack during lookup.
 */
typedef qp_shift qp_key[512];

/*
 * Index word layout.
 *
 * This enum sets up the bit positions of the parts of the index word.
 *
 * In a leaf, the index word contains a pointer. The pointer must be
 * word-aligned so that the tag bit is zero.
 *
 * The bitmap is placed above the tag bit. The bit tests are set up to
 * work directly against the index word; we don't need to extract the
 * bitmap before testing a bit, but we do need to mask the bitmap before
 * calling popcount.
 *
 * The key byte offset is at the top of the word, so that it can be
 * extracted with just a shift, with no masking needed.
 */
enum {
	SHIFT_BRANCH,		// branch / leaf tag
	SHIFT_NOBYTE,		// label separator has no byte value
	SHIFT_BITMAP,		// many bits here
	SHIFT_OFFSET = 48,	// key byte
};

/*
 * Value of the node type tag bit.
 */
#define BRANCH_TAG (W1 << SHIFT_BRANCH)

/*
 * Test a node's tag bit.
 */
static inline bool
isbranch(qp_node *n) {
	return(n->index & BRANCH_TAG);
}

/*
 * Extract a node's offset field.
 */
static inline size_t
keyoff(qp_node *n) {
	return(n->index >> SHIFT_OFFSET);
}

/*
 * Which bit identifies the twig of this node for this key?
 */
static inline qp_shift
twigbit(qp_node *n, const qp_key key, size_t len) {
	size_t off = keyoff(n);
	if(off < len) return(key[off]);
	else return(SHIFT_NOBYTE);
}

/*
 * Is the twig identified by this bit present?
 */
static inline bool
hastwig(qp_node *n, qp_shift bit) {
	return((W1 << bit) & n->index);
}

/*
 * Get the popcount of part of a node's bitmap.
 *
 * The mask covers the lesser bits in the bitmap. Subtract 1 to set the
 * bits, and subtract the branch tag because it is not part of the bitmap.
 */
static inline qp_weight
bmpcount(qp_node *n, qp_shift bit) {
	qp_word mask = (W1 << bit) - 1 - BRANCH_TAG;
	unsigned long long bmp = (unsigned long long)(n->index & mask);
	return((qp_weight)__builtin_popcountll(bmp));
}

/*
 * How many twigs does this node have?
 *
 * The offset is directly after the bitmap so the offset's lesser bits
 * covers the whole bitmap, and its weight is the number of twigs.
 */
static inline qp_weight
twigmax(qp_node *n) {
	return(bmpcount(n, SHIFT_OFFSET));
}

/*
 * Position of a twig within the compressed sparse vector.
 */
static inline qp_weight
twigpos(qp_node *n, qp_shift bit) {
	return(bmpcount(n, bit));
}

/*
 * Get the twig at the given position.
 */
static inline qp_node *
twig(qp_node *n, qp_weight pos) {
	return((qp_node *)n->ptr + pos);
}

/*
 * Lookup table mapping bytes in DNS names to bit positions
 * generated by qp-bits.c
 */
static const uint16_t byte_to_bits[256] = {
	0x0202,	0x0302,	0x0402,	0x0502,	0x0602,	0x0702,	0x0802,	0x0902,
	0x0a02,	0x0b02,	0x0c02,	0x0d02,	0x0e02,	0x0f02,	0x1002,	0x1102,
	0x1202,	0x1302,	0x1402,	0x1502,	0x1602,	0x1702,	0x1802,	0x1902,
	0x1a02,	0x1b02,	0x1c02,	0x1d02,	0x1e02,	0x1f02,	0x2002,	0x2102,
	0x2202,	0x2302,	0x2402,	0x2502,	0x2602,	0x2702,	0x2802,	0x2902,
	0x2a02,	0x2b02,	0x2c02,	0x2d02,	0x2e02,	  0x03,	  0x04,	  0x05,
	  0x06,	  0x07,	  0x08,	  0x09,	  0x0a,	  0x0b,	  0x0c,	  0x0d,
	  0x0e,	  0x0f,	0x0210,	0x0310,	0x0410,	0x0510,	0x0610,	0x0710,
	0x0810,	  0x13,	  0x14,	  0x15,	  0x16,	  0x17,	  0x18,	  0x19,
	  0x1a,	  0x1b,	  0x1c,	  0x1d,	  0x1e,	  0x1f,	  0x20,	  0x21,
	  0x22,	  0x23,	  0x24,	  0x25,	  0x26,	  0x27,	  0x28,	  0x29,
	  0x2a,	  0x2b,	  0x2c,	0x0910,	0x0a10,	0x0b10,	0x0c10,	  0x11,
	  0x12,	  0x13,	  0x14,	  0x15,	  0x16,	  0x17,	  0x18,	  0x19,
	  0x1a,	  0x1b,	  0x1c,	  0x1d,	  0x1e,	  0x1f,	  0x20,	  0x21,
	  0x22,	  0x23,	  0x24,	  0x25,	  0x26,	  0x27,	  0x28,	  0x29,
	  0x2a,	  0x2b,	  0x2c,	0x022d,	0x032d,	0x042d,	0x052d,	0x062d,
	0x072d,	0x082d,	0x092d,	0x0a2d,	0x0b2d,	0x0c2d,	0x0d2d,	0x0e2d,
	0x0f2d,	0x102d,	0x112d,	0x122d,	0x132d,	0x142d,	0x152d,	0x162d,
	0x172d,	0x182d,	0x192d,	0x1a2d,	0x1b2d,	0x1c2d,	0x1d2d,	0x1e2d,
	0x1f2d,	0x202d,	0x212d,	0x222d,	0x232d,	0x242d,	0x252d,	0x262d,
	0x272d,	0x282d,	0x292d,	0x2a2d,	0x2b2d,	0x2c2d,	0x2d2d,	0x2e2d,
	0x2f2d,	0x022e,	0x032e,	0x042e,	0x052e,	0x062e,	0x072e,	0x082e,
	0x092e,	0x0a2e,	0x0b2e,	0x0c2e,	0x0d2e,	0x0e2e,	0x0f2e,	0x102e,
	0x112e,	0x122e,	0x132e,	0x142e,	0x152e,	0x162e,	0x172e,	0x182e,
	0x192e,	0x1a2e,	0x1b2e,	0x1c2e,	0x1d2e,	0x1e2e,	0x1f2e,	0x202e,
	0x212e,	0x222e,	0x232e,	0x242e,	0x252e,	0x262e,	0x272e,	0x282e,
	0x292e,	0x2a2e,	0x2b2e,	0x2c2e,	0x2d2e,	0x2e2e,	0x2f2e,	0x022f,
	0x032f,	0x042f,	0x052f,	0x062f,	0x072f,	0x082f,	0x092f,	0x0a2f,
	0x0b2f,	0x0c2f,	0x0d2f,	0x0e2f,	0x0f2f,	0x102f,	0x112f,	0x122f,
	0x132f,	0x142f,	0x152f,	0x162f,	0x172f,	0x182f,	0x192f,	0x1a2f,
	0x1b2f,	0x1c2f,	0x1d2f,	0x1e2f,	0x1f2f,	0x202f,	0x212f,	0x222f,
	0x232f,	0x242f,	0x252f,	0x262f,	0x272f,	0x282f,	0x292f,	0x2a2f,
};

#endif /* QP_BITS_H */
