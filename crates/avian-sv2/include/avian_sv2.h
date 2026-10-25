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

#include <stddef.h>  /* size_t, which several prototypes below use */
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
    /* The merkle root, on a STANDARD channel. On an extended channel it
     * depends on the extranonce you pick, so this is zero and you call
     * avian_sv2_client_job_header instead. */
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
    /* 1 on an extended channel, 0 on a standard one.
     *
     * On a standard channel the pool built the whole coinbase and handed you a
     * finished merkle root: you can only take its word for what is in the
     * block. On an extended channel you assemble the coinbase yourself from
     * the two halves the pool sent, so you can read every output it commits
     * to, including your own payout. For solo mining that verification is the
     * point. */
    int32_t extended;
    /* How many extranonce bytes you may roll, on an extended channel. 0 on a
     * standard one. */
    uint32_t extranonce_size;
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
    /* Non-zero for an extended channel, which is what a solo miner should
     * want: you assemble the coinbase and can see what you are committing to.
     * Zero for a standard channel. */
    int32_t extended;
    /* The least extranonce to ask for on an extended channel. 0 for the
     * default of 8. The pool refuses the channel if it cannot spare that
     * much, because the scriptSig is only 100 bytes and the height push and
     * the operator tag are in there too. */
    uint32_t min_extranonce_size;
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

/* Submits a share for an extended job, naming the extranonce you hashed.
 *
 * The pool reassembles the same coinbase and folds the same path, so it has to
 * be told which extranonce produced the root. Pass extranonce_len 0 on a
 * standard channel, or use avian_sv2_client_submit. */
int32_t avian_sv2_client_submit_extended(AvianSv2Client *client,
                                         const AvianMiningJob *job,
                                         uint32_t nonce, uint32_t ntime,
                                         const uint8_t *extranonce,
                                         size_t extranonce_len);

/* The 80 header bytes for a job at an extranonce, ntime and nonce.
 *
 * Works for both kinds of channel: on a standard one the extranonce is ignored
 * and the pool's merkle root used, on an extended one the coinbase is
 * assembled and the path folded. Does not hash. out needs 80 bytes. */
int32_t avian_sv2_client_job_header(AvianSv2Client *client, uint32_t job_id,
                                    const uint8_t *extranonce,
                                    size_t extranonce_len, uint32_t ntime,
                                    uint32_t nonce, uint8_t *out);

/* The coinbase an extended job commits to, without witness.
 *
 * This is what extended channels are for: read the outputs instead of taking
 * the pool's word for a merkle root. Writes at most capacity bytes and sets
 * *written to the full length, so calling once with capacity 0 sizes a
 * buffer.
 *
 * That sizing call returns AVIAN_SV2_OK, so the two-call pattern works for a
 * caller that checks the status, which every caller should:
 *
 *     size_t needed = 0;
 *     if (avian_sv2_client_job_coinbase(c, id, xn, xn_len, NULL, 0, &needed)
 *         != AVIAN_SV2_OK) { ... }
 *     uint8_t *buf = malloc(needed);
 *     if (avian_sv2_client_job_coinbase(c, id, xn, xn_len, buf, needed,
 *                                       &needed) != AVIAN_SV2_OK) { ... }
 *
 * A non-zero capacity smaller than the coinbase is a caller error: it returns
 * AVIAN_SV2_INVALID_ARGUMENT with a message, and *written is still set. */
int32_t avian_sv2_client_job_coinbase(AvianSv2Client *client, uint32_t job_id,
                                      const uint8_t *extranonce,
                                      size_t extranonce_len, uint8_t *out,
                                      size_t capacity, size_t *written);

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

/* Checks that this header agrees with the library about struct layout.
 *
 * The header is written by hand, so a field added to the Rust side in the
 * wrong place would make every struct member after it read the wrong bytes,
 * and a job whose ntime or target silently shifted would mine garbage rather
 * than fail. Call it once at startup with sizeof and offsetof and it answers
 * before that can happen:
 *
 *     avian_sv2_abi_check(sizeof(AvianMiningJob),
 *                         offsetof(AvianMiningJob, extranonce_size),
 *                         sizeof(AvianSv2Event),
 *                         offsetof(AvianSv2Event, message))
 *
 * Returns AVIAN_SV2_OK or AVIAN_SV2_ERROR. */
int32_t avian_sv2_abi_check(size_t job_size, size_t job_extranonce_size_offset,
                            size_t event_size, size_t event_message_offset);

#ifdef __cplusplus
}
#endif

#endif /* AVIAN_SV2_H */
