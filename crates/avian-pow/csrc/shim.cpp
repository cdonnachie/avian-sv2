// A C entry point for Avian's two proof-of-work hashes.
//
// HashX16R and Minotaurx are inline templates in Avian's own headers, so this
// does not reimplement anything: it instantiates them and copies the bytes
// out. Nothing from Bitcoin Core's node code is pulled in, only uint256 and
// the algorithm sources that CMakeLists lists.
//
// CBlockHeader::ComputePoWHash derives X16RT's seed as
// SHA256d(nTime & 0xffffff80) and hands it to HashX16R; here the caller
// supplies the seed already hashed, so the shim stays free of hash.h.

#include <algo/minotaurx/minotaurx.h>
#include <algo/x16r/x16r.h>

#include <yespower/crypto/sha256.h>

#include <cstring>

// Avian's TIME_MASK, from primitives/block.h.
static const uint32_t AVIAN_TIME_MASK = 0xffffff80;

extern "C" {

// SHA256d of nTime masked to its 128-second epoch, which is the seed
// CBlockHeader::ComputePoWHash hands to HashX16R. Kept on this side so the
// caller cannot get the mask or the double hash wrong.
void avian_x16rt_seed(uint32_t ntime, unsigned char out32[32])
{
    const uint32_t masked = ntime & AVIAN_TIME_MASK;
    unsigned char first[32];
    SHA256_Buf(&masked, sizeof(masked), first);
    SHA256_Buf(first, sizeof(first), out32);
}

void avian_x16rt_hash(const unsigned char* header,
                      unsigned long header_len,
                      const unsigned char seed32[32],
                      unsigned char out32[32])
{
    const uint256 seed{std::span<const unsigned char>{seed32, 32}};
    const uint256 hash{HashX16R(header, header + header_len, seed)};
    std::memcpy(out32, hash.data(), 32);
}

void avian_minotaurx_hash(const unsigned char* header,
                          unsigned long header_len,
                          unsigned char out32[32])
{
    // minotaurX = true selects the yespower-terminated variant, which is what
    // POW_TYPE_MINOTAURX uses. A null yespower_local_t makes Minotaurx use a
    // stack-local one.
    const uint256 hash{Minotaurx(header, header + header_len, true, nullptr)};
    std::memcpy(out32, hash.data(), 32);
}

} // extern "C"
