#include "sphincs.h"
#include "time.h"
#include "os.h"
#include "wd.h"
#include "usb_device.h"

#include <string.h>
#include "randombytes.h"
#include "api.h"

/* logging removed */

// Default algorithm (can be overridden at compile time)
#ifndef SPHINCS_ALG_NAME
#define SPHINCS_ALG_NAME "Sphincs+-SHA2-128f-simple"
#endif

static bool _initialized = false;

// SPHINCS+-SHA2-128f-simple key sizes
static u8 _sk[PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES] __attribute__((aligned(4)));
static u8 _pk[PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES] __attribute__((aligned(4)));

// Custom random number generator for embedded systems
static uint32_t _rand_state = 0;


static int _embedded_randombytes(uint8_t *random_array, size_t bytes_to_read)
{
    uint32_t seed = _rand_state;
    if (seed == 0) {
        extern uint32_t _estack;
        seed = (uint32_t)timer_get_time() ^ (uint32_t)&_estack;
        if (seed == 0) seed = 0x12345678;
        _rand_state = seed;
    }
    
    for (size_t i = 0; i < bytes_to_read; i++) {
        seed = (seed * 1103515245UL + 12345UL) & 0x7fffffffUL;
        random_array[i] = (uint8_t)(seed & 0xff);
        seed = (seed * 1103515245UL + 12345UL) & 0x7fffffffUL;
        random_array[i] ^= (uint8_t)((seed >> 8) & 0xff);
    }
    _rand_state = seed;
    return 0;
}

// Implement PQClean's randombytes() API
int randombytes(uint8_t *output, size_t n)
{
    return _embedded_randombytes(output, n);
}

// Early initialization for RNG state
void sphincs_init_early(void)
{
    (void)0;
}

bool sphincs_init(void)
{
    if (_initialized) return true;

    

    // Extend watchdog during potentially long key generation
    #define WD_TIMEOUT_LONG 30000
    wd_set_timeout(WD_TIMEOUT_LONG);
    wd_feed();
    usb_device_task();
    

    uint8_t seed[PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_SEEDBYTES];
    _embedded_randombytes(seed, sizeof(seed));
    
    if (PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_seed_keypair(_pk, _sk, seed) != 0)
    {
        
        wd_set_timeout(300);
        return false;
    }

    _initialized = true;
    

    // Restore normal WD timeout
    wd_set_timeout(300);
    return true;
}

u32 sphincs_signature_max_len(void)
{
    return (u32)PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_CRYPTO_BYTES;
}

bool sphincs_sign(const u8 *msg, u32 msg_len, u8 *sig_out, u32 *out_len, u32 *time_us)
{
    

    if (!_initialized && !sphincs_init())
    {
        
        return false;
    }

    size_t sig_len = 0;
    #define WD_TIMEOUT_LONG 30000
    wd_set_timeout(WD_TIMEOUT_LONG);
    wd_feed();
    usb_device_task();
    
    os_timer_t t0 = timer_get_time();
    if (PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature(sig_out, &sig_len,
                                              (const uint8_t *)msg, (size_t)msg_len,
                                              _sk) != 0)
    {
        
        wd_set_timeout(300);
        return false;
    }
    os_timer_t t1 = timer_get_time();

    if (out_len) *out_len = (u32)sig_len;
    if (time_us) *time_us = (u32)(t1 - t0);
    
    wd_feed();
    usb_device_task();
    wd_set_timeout(300);
    
    return true;
}

bool sphincs_verify(const u8 *msg, u32 msg_len, const u8 *sig, u32 sig_len, u32 *time_us)
{
    if (!_initialized && !sphincs_init())
        return false;

    // Extend watchdog during potentially long verify
    #define WD_TIMEOUT_LONG 30000
    wd_set_timeout(WD_TIMEOUT_LONG);
    wd_feed();
    usb_device_task();

    os_timer_t t0 = timer_get_time();
    int rc = PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(sig, (size_t)sig_len,
                              (const uint8_t *)msg, (size_t)msg_len, _pk);
    os_timer_t t1 = timer_get_time();

    if (time_us) *time_us = (u32)(t1 - t0);

    wd_feed();
    usb_device_task();
    wd_set_timeout(300);

    return (rc == 0);
}

