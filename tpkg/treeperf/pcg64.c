/*
 * (c) 2014 M.E. O'Neill / pcg-random.org
 * Licensed under Apache License 2.0 (NO WARRANTY, etc. see website)
 *
 * nearly-divisionless random numbers by Daniel Lemire
 * https://lemire.me/blog?p=17551
 *
 * this version adapted by Tony Finch <dot@dotat.at>
 */

#include "config.h"

#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#ifdef HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif
#include <unistd.h>

#include "pcg64.h"

static void
randomize(void *buf, size_t len) {
#ifdef HAVE_GETRANDOM
	if(getrandom(buf, len, 0) < 0)
		err(1, "getrandom");
#else
        int fd = open("/dev/urandom", O_RDONLY);
        if(fd < 0) err(1, "open /dev/urandom");
        ssize_t n = read(fd, buf, len);
        if(n < (ssize_t)len) err(1, "read /dev/urandom");
        close(fd);
#endif
}

void
pcg64_getentropy(pcg64_t *rng) {
        randomize(rng, sizeof(*rng));
        pcg64_seed(rng, rng->state, rng->inc);
}

void
pcg64_seed(pcg64_t *rng, uint128_t state, uint128_t seq) {
        rng->state = 0U;
        rng->inc = (seq << 1) | 1u;
        pcg64(rng);
        rng->state += state;
        pcg64(rng);
}

/*
 * Regenerate `num` if it is one of `residue = (1 << 64) % limit` biased
 * values, so that the return value is sampled from `(1 << 64) - residue
 * == N * limit` random values, for the largest possible `N`.
 */
uint64_t
pcg64_limit_slow(pcg64_t *rng, uint64_t limit, uint128_t num) {
	uint64_t residue = -limit % limit;
	while(uint128_lo64(num) < residue)
		num = pcg64_limit_frac(rng, limit);
        return(uint128_hi64(num));
}
