/*
 * (c) 2014 M.E. O'Neill / pcg-random.org
 * Licensed under Apache License 2.0 (NO WARRANTY, etc. see website)
 *
 * nearly-divisionless random numbers by Daniel Lemire
 * https://lemire.me/blog?p=17551
 *
 * this version adapted by Tony Finch <dot@dotat.at>
 */

#ifndef PCG64_H
#define PCG64_H

typedef __uint128_t uint128_t;

#define uint128_lo64(u) ((uint64_t)(u))
#define uint128_hi64(u) ((u) >> 64)

typedef struct pcg64 {
        uint128_t state;
        uint128_t inc;
} pcg64_t;

/* initializers */
void pcg64_seed(pcg64_t *rng, uint128_t state, uint128_t seq);
void pcg64_getentropy(pcg64_t *rng);

#define PCG_128BIT_CONSTANT(high,low) \
        ((((uint128_t)high) << 64) | (uint128_t)low)

#define PCG_MULTIPLIER_128						\
        PCG_128BIT_CONSTANT(2549297995355413924ULL,4865540595714422341ULL)

static inline uint64_t
pcg64(pcg64_t *rng) {
	uint64_t xor, rot;
	/* linear congruential generator */
        rng->state = rng->state * PCG_MULTIPLIER_128 + rng->inc;
	/* permuted output */
        xor = uint128_lo64(rng->state) ^ uint128_hi64(rng->state);
        rot = rng->state >> 122;
        return((xor >> rot) | (xor << (-rot & 63)));
}

/*
 * Get a 64.64 fixed-point value less than limit. The fraction
 * part (lower 64 bits) is used to determine whether or not the
 * integer part (upper 64 bits) is biased.
 */
static inline uint128_t
pcg64_limit_frac(pcg64_t *rng, uint64_t limit) {
        return((uint128_t)pcg64(rng) * (uint128_t)limit);
}

/*
 * Slowly but accurately check if num is biased, and regenerate it until
 * it is not. Returns an unbiased random integer less than limit.
 */
uint64_t pcg64_limit_slow(pcg64_t *rng, uint64_t limit, uint128_t num);

/*
 * Get an unbiased random integer less than limit. Nearly always fast.
 */
static inline uint64_t
pcg64_limit(pcg64_t *rng, uint64_t limit) {
        uint128_t num = pcg64_limit_frac(rng, limit);
        if(uint128_lo64(num) < limit)
		return(pcg64_limit_slow(rng, limit, num));
        return(uint128_hi64(num));
}

#endif /* PCG64_H */
