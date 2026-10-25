/* Avian's X16RT and MinotaurX, linked from Avian Core's own sources.
 *
 * This is NOT part of libavian-sv2, and the separation is deliberate.
 * libavian-sv2 does the protocol and no hashing; a miner brings its own
 * optimised hasher. This library exists for the two consumers that are not
 * miners: the pool, which has to check a share, and a C program standing in
 * for a miner's hasher.
 *
 *     cc -I crates/avian-sv2/include -I crates/avian-pow/include my.c \
 *        target/release/libavian_sv2.a target/release/libavian_pow.a \
 *        -lstdc++ -lpthread -ldl -lm -o my
 *
 * libstdc++ is needed because Avian's lyra2, sponge, tiger and uint256 are
 * C++. Build avian-pow with AVIAN_SRC pointing at the Avian Core src
 * directory, or with the tree beside this repository.
 */

#ifndef AVIAN_POW_H
#define AVIAN_POW_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AVIAN_POW_OK 0
#define AVIAN_POW_INVALID_ARGUMENT -2
#define AVIAN_POW_UNAVAILABLE -3

#define AVIAN_POW_X16RT 0
#define AVIAN_POW_MINOTAURX 1

/* Hashes a header and writes 32 bytes to out32, in uint256's internal
 * little-endian order, which is the order a target is compared in and the
 * reverse of how a block hash is printed. */
int32_t avian_pow_hash(int32_t pow_type, const uint8_t *header,
                       size_t header_len, uint8_t *out32);

/* Whether the hashers were compiled in. 1 or 0. */
int32_t avian_pow_available(void);

#ifdef __cplusplus
}
#endif

#endif /* AVIAN_POW_H */
