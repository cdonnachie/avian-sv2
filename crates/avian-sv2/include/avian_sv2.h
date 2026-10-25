/* libavian-sv2: Avian Stratum v2 for a C miner.
 *
 * The C side sees jobs and submits shares. It never sees Noise, framing or a
 * Stratum v2 type, and it does no protocol work of its own.
 *
 * What this library does NOT do, deliberately: X16RT, MinotaurX, CUDA or any
 * hashing. avian_sv2_build_header gives you the 80 bytes; hashing them is
 * yours, and having an optimised hasher is the entire reason you are a miner.
 *
 * Linking (Linux, from the workspace root):
 *
 *     cargo build --release -p avian-sv2
 *     cc -I crates/avian-sv2/include my_miner.c \
 *        target/release/libavian_sv2.a -lpthread -ldl -lm -o my_miner
 *
 * The static library carries the whole Rust standard library, so nothing else
 * is needed beyond libc, libm, libdl and libpthread. Build it with
 * AVIAN_SRC unset: this library needs no Avian source tree, because it does no
 * hashing.
 *
 * Threading: a handle is not synchronised. Use it from one thread, or guard it
 * yourself. Polling and submitting from two threads at once is not supported.
 */

#ifndef AVIAN_SV2_H
#define AVIAN_SV2_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes. Negative values are failures. */
#define AVIAN_SV2_OK 0
#define AVIAN_SV2_TIMEOUT 1
#define AVIAN_SV2_DISCONNECTED 2
#define AVIAN_SV2_ERROR -1
#define AVIAN_SV2_INVALID_ARGUMENT -2

/* Proof-of-work algorithms, matching nVersion bits 16-23. */
#define AVIAN_SV2_POW_X16RT 0
#define AVIAN_SV2_POW_MINOTAURX 1

/* Event kinds. */
#define AVIAN_SV2_EVENT_NONE 0
#define AVIAN_SV2_EVENT_JOB 1
#define AVIAN_SV2_EVENT_JOBS_INVALIDATED 2
#define AVIAN_SV2_EVENT_SHARE_ACCEPTED 3
#define AVIAN_SV2_EVENT_SHARE_REJECTED 4
#define AVIAN_SV2_EVENT_RECONNECTED 5
#define AVIAN_SV2_EVENT_DISCONNECTED 6

#define AVIAN_SV2_MESSAGE_LEN 256

/* A job, in a form that knows nothing about Stratum v2.
 *
 * There is no network_target, and its absence is the contract: a standard
 * channel is told only its share target. Whether a share is also a block is
 * the pool's determination, because only the pool holds the template, and the
 * pool forwards a winning share to the node itself.
 *
 * prev_hash, merkle_root and share_target are all in uint256's internal
 * little-endian order, which is the order they go into the header and the
 * order avian_sv2_meets_target compares in. It is the reverse of how a block
 * hash is printed. */
typedef struct {
    uint32_t job_id;
    /* Which connection this job came from. A reconnect bumps it and job ids
     * start again, so throw away work in flight from an earlier generation:
     * a share against a stale job id is refused, or worse, applied to a
     * different job that now has that id. */
    uint64_t generation;
    int32_t pow_type;
    uint32_t version;
    uint8_t prev_hash[32];
    uint8_t merkle_root[32];
    /* Where to start, which equals ntime_min. */
    uint32_t ntime;
    /* Inclusive at both ends. Rolling outside this window is what
     * AvianJobTimeConstraints exists to prevent: past the end of an X16RT
     * 128-second epoch the hash chain changes and you compute a different
     * function, silently. On regtest and testnet the window is pinned shut,
     * ntime_min == ntime_max, because nBits there is a function of nTime. */
    uint32_t ntime_min;
    uint32_t ntime_max;
    uint32_t nbits;
    uint8_t share_target[32];
} AvianMiningJob;

typedef struct {
    int32_t kind;
    /* Meaningful when kind == AVIAN_SV2_EVENT_JOB. */
    AvianMiningJob job;
    uint32_t sequence_number;
    /* Shares accepted so far, or the attempt count on a reconnect. */
    uint32_t accepted_count;
    uint64_t generation;
    /* NUL-terminated: the refusal code for a rejected share, or the reason for
     * a disconnect. */
    char message[AVIAN_SV2_MESSAGE_LEN];
} AvianSv2Event;

typedef struct {
    /* "host:port", NUL-terminated. Loopback only. */
    const char *pool;
    /* The pool's authority x-only public key as 64 hex characters, or NULL for
     * trust on first use. NULL leaves the session encrypted but says nothing
     * about whether the peer is the pool you meant. */
    const char *authority_hex;
    int32_t pow_type;
    /* May be NULL. */
    const char *user_identity;
    float nominal_hash_rate;
    /* 0 for the default, 30s. */
    uint32_t timeout_ms;
    /* 0 for the defaults: 250ms doubling to 30s. */
    uint32_t backoff_initial_ms;
    uint32_t backoff_max_ms;
    /* 0 retries forever, which is what a miner wants. */
    uint32_t max_reconnects;
} AvianSv2ClientConfig;

typedef struct AvianSv2Client AvianSv2Client;

/* Connects, negotiates the 0x4001 extension, selects the algorithm and opens a
 * standard channel. Returns NULL on failure with *status set; the reason is
 * available from avian_sv2_last_connect_error(). status may be NULL. */
AvianSv2Client *avian_sv2_client_connect(const AvianSv2ClientConfig *config,
                                         int32_t *status);

/* Why the last connect on this thread failed. Owned by the library, valid
 * until the next connect call on the same thread. */
const char *avian_sv2_last_connect_error(void);

/* Reads one event, waiting at most timeout_ms.
 *
 * AVIAN_SV2_TIMEOUT with kind NONE means nothing arrived, which is the normal
 * case while hashing. AVIAN_SV2_DISCONNECTED means the connection dropped; the
 * next call reconnects and reports AVIAN_SV2_EVENT_RECONNECTED. You may treat
 * both as "keep going", so long as you discard jobs whose generation is no
 * longer current. */
int32_t avian_sv2_client_poll(AvianSv2Client *client, uint32_t timeout_ms,
                              AvianSv2Event *event);

/* Submits a share for the job you were handed.
 *
 * Takes the job rather than its id: a job id is only unique within a
 * generation, so submitting by id alone would let a nonce found for job 1 of
 * one connection be applied to job 1 of the next.
 *
 * The version comes from the job, not from you: an Avian mining connection
 * sets REQUIRES_FIXED_VERSION, and nVersion bits 16-23 are the algorithm, so
 * changing them moves the share to the other algorithm's proof-of-work
 * limit. */
int32_t avian_sv2_client_submit(AvianSv2Client *client,
                                const AvianMiningJob *job, uint32_t nonce,
                                uint32_t ntime);

/* Closes the connection so the next poll reconnects. For failover. */
int32_t avian_sv2_client_disconnect(AvianSv2Client *client);

/* The last error on this handle. Owned by the library. */
const char *avian_sv2_last_error(const AvianSv2Client *client);

/* Frees a handle. NULL is accepted and ignored, like free(3). */
void avian_sv2_client_free(AvianSv2Client *client);

/* Assembles the 80 header bytes for a job at an ntime and nonce. Does not hash
 * them. out must have room for 80 bytes. */
int32_t avian_sv2_build_header(const AvianMiningJob *job, uint32_t ntime,
                               uint32_t nonce, uint8_t *out);

/* Whether a 32-byte proof-of-work hash is at or under a 32-byte target. Both
 * are in uint256's internal little-endian order. Returns 1, 0, or a negative
 * status. */
int32_t avian_sv2_meets_target(const uint8_t *hash, const uint8_t *target);

/* The library version, NUL-terminated and statically allocated. */
const char *avian_sv2_version(void);

#ifdef __cplusplus
}
#endif

#endif /* AVIAN_SV2_H */
