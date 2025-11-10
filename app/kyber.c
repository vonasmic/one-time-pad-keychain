#include "kyber.h"
#include "time.h"
#include "os.h"
#include "wd.h"
#include "usb_device.h"

#include <string.h>
#include "randombytes.h"

// Use PQClean ML-KEM-768 (Kyber768) clean implementation
#include "../PQClean/crypto_kem/ml-kem-768/clean/api.h"

static bool _initialized = false;

static u8 _sk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES] __attribute__((aligned(4)));
static u8 _pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES] __attribute__((aligned(4)));

bool kyber_init(void)
{
	if (_initialized) return true;

	#define WD_TIMEOUT_LONG 30000
	wd_set_timeout(WD_TIMEOUT_LONG);
	wd_feed();
	usb_device_task();

	if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(_pk, _sk) != 0)
	{
		wd_set_timeout(300);
		return false;
	}

	_initialized = true;
	wd_set_timeout(300);
	return true;
}

u32 kyber_ciphertext_len(void)
{
	return (u32)PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES;
}

u32 kyber_sharedsecret_len(void)
{
	return (u32)PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES;
}

bool kyber_encapsulate(u8 *ct_out, u8 *ss_out, u32 *time_us)
{
	if (!_initialized && !kyber_init())
		return false;

	#define WD_TIMEOUT_LONG 30000
	wd_set_timeout(WD_TIMEOUT_LONG);
	wd_feed();
	usb_device_task();

	os_timer_t t0 = timer_get_time();
	int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct_out, ss_out, _pk);
	os_timer_t t1 = timer_get_time();

	if (time_us) *time_us = (u32)(t1 - t0);

	wd_feed();
	usb_device_task();
	wd_set_timeout(300);

	return (rc == 0);
}

bool kyber_decapsulate(const u8 *ct, u8 *ss_out, u32 *time_us)
{
	if (!_initialized && !kyber_init())
		return false;

	#define WD_TIMEOUT_LONG 30000
	wd_set_timeout(WD_TIMEOUT_LONG);
	wd_feed();
	usb_device_task();

	os_timer_t t0 = timer_get_time();
	int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss_out, ct, _sk);
	os_timer_t t1 = timer_get_time();

	if (time_us) *time_us = (u32)(t1 - t0);

	wd_feed();
	usb_device_task();
	wd_set_timeout(300);

	return (rc == 0);
}



