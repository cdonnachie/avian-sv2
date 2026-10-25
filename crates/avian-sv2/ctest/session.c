/* A C miner, in the shape a real one would take.
 *
 * This exists because an API exercised only from the language that defined it
 * is self-consistent and proves nothing about the consumer that matters. It is
 * compiled by a C compiler, linked against the static libraries, and run
 * against a real pool backed by a real node.
 *
 * It is also the demonstration of the boundary: the protocol comes from
 * libavian-sv2 and the hashing comes from somewhere else entirely, here
 * libavian_pow standing in for a miner's own optimised code. libavian-sv2
 * contains no X16RT and no MinotaurX, on purpose.
 *
 *     ./session <host:port> <pool authority> <x16rt|minotaurx> <payout address>
 *
 * The payout address is where a solo pool sends the block reward, so it goes
 * in user_identity as `address.workername`. A pool refuses the channel if it
 * does not parse, which is the only safe thing it can do: there is no sane
 * fallback for "I could not read where to send the money".
 *
 * Prints what happened, one line per step, and exits 0 only if a share was
 * accepted.
 */

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "avian_pow.h"
#include "avian_sv2.h"

/* How many nonces to try. On regtest the target is the algorithm's own floor,
 * so a handful is enough; the bound only exists so a broken build fails
 * instead of looping. */
#define MAX_NONCES 20000

/* Avian has no cheap pre-filter: the only way to know whether a nonce is good
 * is to compute the whole hash. This is the loop a real miner replaces with
 * something fast, and the reason it is here and not in the library.
 *
 * On an extended channel the extranonce is search space too, and the header
 * has to be rebuilt through the library each time because the coinbase, and so
 * the merkle root, changes with it. */
static int search_extended(AvianSv2Client *client, const AvianMiningJob *job,
                           uint8_t *extranonce, uint32_t *found_nonce) {
    uint8_t header[80];
    uint8_t hash[32];

    for (uint32_t counter = 0; counter < 64; counter++) {
        memset(extranonce, 0, job->extranonce_size);
        size_t take = sizeof(counter) < job->extranonce_size ? sizeof(counter)
                                                             : job->extranonce_size;
        memcpy(extranonce, &counter, take);
        for (uint32_t nonce = 0; nonce < 256; nonce++) {
            if (avian_sv2_client_job_header(client, job->job_id, extranonce,
                                            job->extranonce_size, job->ntime, nonce,
                                            header) != AVIAN_SV2_OK) {
                fprintf(stderr, "job_header failed: %s\n", avian_sv2_last_error(client));
                return 0;
            }
            if (avian_pow_hash(job->pow_type, header, sizeof(header), hash) != AVIAN_POW_OK) {
                fprintf(stderr, "avian_pow_hash failed\n");
                return 0;
            }
            if (avian_sv2_meets_target(hash, job->share_target) == 1) {
                *found_nonce = nonce;
                return 1;
            }
        }
    }
    return 0;
}

static int search(const AvianMiningJob *job, uint32_t *found_nonce) {
    uint8_t header[80];
    uint8_t hash[32];

    for (uint32_t nonce = 0; nonce < MAX_NONCES; nonce++) {
        if (avian_sv2_build_header(job, job->ntime, nonce, header) != AVIAN_SV2_OK) {
            fprintf(stderr, "build_header failed\n");
            return 0;
        }
        if (avian_pow_hash(job->pow_type, header, sizeof(header), hash) != AVIAN_POW_OK) {
            fprintf(stderr, "avian_pow_hash failed\n");
            return 0;
        }
        if (avian_sv2_meets_target(hash, job->share_target) == 1) {
            *found_nonce = nonce;
            return 1;
        }
    }
    return 0;
}

static void print_hex(const char *label, const uint8_t *bytes, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr,
                "usage: %s <host:port> <authority> <x16rt|minotaurx> <payout address>\n",
                argv[0]);
        return 2;
    }

    int32_t pow_type;
    if (strcmp(argv[3], "x16rt") == 0) {
        pow_type = AVIAN_SV2_POW_X16RT;
    } else if (strcmp(argv[3], "minotaurx") == 0) {
        pow_type = AVIAN_SV2_POW_MINOTAURX;
    } else {
        fprintf(stderr, "unknown algorithm %s\n", argv[3]);
        return 2;
    }

    printf("linked libavian-sv2 %s, hashers %s\n", avian_sv2_version(),
           avian_pow_available() ? "available" : "UNAVAILABLE");
    if (!avian_pow_available()) {
        fprintf(stderr, "no hashers, so no share could be found\n");
        return 1;
    }

    /* user_identity is `address.workername`, the Stratum v1 convention carried
     * into v2 and what a miner's UI labels "User". The label is the operator's
     * to read; only the address affects the payout. */
    char identity[320];
    int written = snprintf(identity, sizeof(identity), "%s.c-miner", argv[4]);
    if (written < 0 || (size_t)written >= sizeof(identity)) {
        fprintf(stderr, "payout address is too long\n");
        return 2;
    }

    /* The header is hand written, so check it agrees with the library about
     * struct layout before trusting a single field. */
    if (avian_sv2_abi_check(sizeof(AvianMiningJob),
                            offsetof(AvianMiningJob, extranonce_size),
                            sizeof(AvianSv2Event),
                            offsetof(AvianSv2Event, message))
        != AVIAN_SV2_OK) {
        fprintf(stderr, "avian_sv2.h disagrees with the library about struct layout\n");
        return 1;
    }

    AvianSv2ClientConfig config;
    memset(&config, 0, sizeof(config));
    config.pool = argv[1];
    config.authority_hex = argv[2];
    config.pow_type = pow_type;
    config.user_identity = identity;
    config.nominal_hash_rate = 1.0f;
    config.timeout_ms = 30000;
    config.backoff_initial_ms = 50;
    config.backoff_max_ms = 500;
    config.max_reconnects = 20;
    /* Extended, which is what a solo miner should want: the coinbase is
     * assembled here and can be inspected, rather than arriving as a merkle
     * root to be trusted. AVIAN_SV2_EXTENDED=0 asks for a standard channel
     * instead, so both paths get exercised. */
    const char *want_standard = getenv("AVIAN_SV2_EXTENDED");
    config.extended = (want_standard != NULL && strcmp(want_standard, "0") == 0) ? 0 : 1;
    config.min_extranonce_size = 8;

    int32_t status = AVIAN_SV2_OK;
    AvianSv2Client *client = avian_sv2_client_connect(&config, &status);
    if (client == NULL) {
        fprintf(stderr, "connect failed (%d): %s\n", status, avian_sv2_last_connect_error());
        return 1;
    }
    printf("connected and opened %s channel, paying %s\n",
           config.extended ? "an extended" : "a standard", argv[4]);

    AvianMiningJob job;
    int have_job = 0;
    int accepted = 0;
    int submitted = 0;
    int reconnects = 0;

    /* The shape of a miner's main loop: poll for protocol events, hash between
     * polls, submit when something is found. */
    for (int round = 0; round < 2000 && !accepted; round++) {
        AvianSv2Event event;
        status = avian_sv2_client_poll(client, 200, &event);

        if (status == AVIAN_SV2_ERROR) {
            fprintf(stderr, "poll failed: %s\n", event.message);
            avian_sv2_client_free(client);
            return 1;
        }

        switch (event.kind) {
        case AVIAN_SV2_EVENT_JOB:
            job = event.job;
            have_job = 1;
            submitted = 0;
            printf("job %" PRIu32 " generation %" PRIu64 " algo %" PRId32
                   " ntime %" PRIu32 "..%" PRIu32 " nbits %08" PRIx32 "\n",
                   job.job_id, job.generation, job.pow_type, job.ntime_min, job.ntime_max,
                   job.nbits);
            print_hex("  prev_hash     ", job.prev_hash, 32);
            print_hex("  merkle_root   ", job.merkle_root, 32);
            print_hex("  share_target  ", job.share_target, 32);
            if (job.extended) {
                /* What a standard channel cannot do: read the coinbase this
                 * block commits to, rather than taking the pool's word for a
                 * merkle root. A real miner would check its own payout script
                 * is in here. */
                uint8_t extranonce[32];
                size_t needed = 0;
                memset(extranonce, 0, sizeof(extranonce));
                if (job.extranonce_size > sizeof(extranonce)) {
                    fprintf(stderr, "extranonce is larger than this program expects\n");
                    avian_sv2_client_free(client);
                    return 1;
                }
                /* The sizing call's status is checked, not ignored. It is
                 * the documented way to learn the length, so a caller
                 * following the header must be able to trust it. */
                if (avian_sv2_client_job_coinbase(client, job.job_id, extranonce,
                                                  job.extranonce_size, NULL, 0,
                                                  &needed)
                    != AVIAN_SV2_OK) {
                    fprintf(stderr, "sizing the coinbase failed: %s\n",
                            avian_sv2_last_error(client));
                    avian_sv2_client_free(client);
                    return 1;
                }
                /* And a buffer one byte short is refused rather than
                 * truncating, with something to print. */
                size_t short_written = 0;
                uint8_t one_byte = 0;
                if (needed > 1
                    && avian_sv2_client_job_coinbase(client, job.job_id, extranonce,
                                                     job.extranonce_size, &one_byte,
                                                     1, &short_written)
                           == AVIAN_SV2_OK) {
                    fprintf(stderr, "a 1-byte buffer was accepted for a %zu-byte coinbase\n",
                            needed);
                    avian_sv2_client_free(client);
                    return 1;
                }
                uint8_t *coinbase = malloc(needed);
                if (coinbase == NULL
                    || avian_sv2_client_job_coinbase(client, job.job_id, extranonce,
                                                     job.extranonce_size, coinbase, needed,
                                                     &needed)
                           != AVIAN_SV2_OK) {
                    fprintf(stderr, "could not read the coinbase: %s\n",
                            avian_sv2_last_error(client));
                    free(coinbase);
                    avian_sv2_client_free(client);
                    return 1;
                }
                printf("  extended: %u extranonce bytes, a %zu-byte coinbase I assembled\n",
                       job.extranonce_size, needed);
                free(coinbase);
            }
            break;

        case AVIAN_SV2_EVENT_JOBS_INVALIDATED:
            printf("the tip moved, so every job before generation %" PRIu64 " is dead\n",
                   event.generation);
            have_job = 0;
            break;

        case AVIAN_SV2_EVENT_SHARE_ACCEPTED:
            printf("share %" PRIu32 " accepted, %" PRIu32 " so far\n", event.sequence_number,
                   event.accepted_count);
            accepted = 1;
            break;

        case AVIAN_SV2_EVENT_SHARE_REJECTED:
            printf("share %" PRIu32 " rejected: %s\n", event.sequence_number, event.message);
            submitted = 0;
            break;

        case AVIAN_SV2_EVENT_DISCONNECTED:
            printf("disconnected: %s\n", event.message);
            have_job = 0;
            break;

        case AVIAN_SV2_EVENT_RECONNECTED:
            printf("reconnected as generation %" PRIu64 " after %" PRIu32 " attempt(s)\n",
                   event.generation, event.accepted_count);
            reconnects++;
            have_job = 0;
            break;

        default:
            break;
        }

        if (have_job && !submitted) {
            uint32_t nonce = 0;
            uint8_t extranonce[32];
            memset(extranonce, 0, sizeof(extranonce));
            int found = job.extended
                            ? search_extended(client, &job, extranonce, &nonce)
                            : search(&job, &nonce);
            if (!found) {
                printf("no nonce found for job %" PRIu32 "\n", job.job_id);
                continue;
            }
            status = job.extended
                         ? avian_sv2_client_submit_extended(client, &job, nonce, job.ntime,
                                                            extranonce, job.extranonce_size)
                         : avian_sv2_client_submit(client, &job, nonce, job.ntime);
            if (status == AVIAN_SV2_OK) {
                printf("submitted nonce %" PRIu32 " ntime %" PRIu32 " for job %" PRIu32 "\n",
                       nonce, job.ntime, job.job_id);
                submitted = 1;
            } else {
                printf("submit refused locally (%d): %s\n", status, avian_sv2_last_error(client));
                have_job = 0;
            }
        }
    }

    /* Prove the reconnect path works from C too, since that is the half a
     * miner cannot do without. */
    if (accepted) {
        printf("forcing a reconnect\n");
        avian_sv2_client_disconnect(client);
        for (int round = 0; round < 200; round++) {
            AvianSv2Event event;
            avian_sv2_client_poll(client, 200, &event);
            if (event.kind == AVIAN_SV2_EVENT_RECONNECTED) {
                printf("reconnected as generation %" PRIu64 "\n", event.generation);
                reconnects++;
                break;
            }
        }
        if (reconnects == 0) {
            fprintf(stderr, "never reconnected\n");
            avian_sv2_client_free(client);
            return 1;
        }
    }

    avian_sv2_client_free(client);
    if (!accepted) {
        fprintf(stderr, "no share was accepted\n");
        return 1;
    }
    printf("done: a share was accepted and the connection was re-established\n");
    return 0;
}
