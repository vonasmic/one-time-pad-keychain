#include "dilithium.h"
#include "time.h"
#include "os.h"
#include "wd.h"
#include "usb_device.h"

#include <string.h>
#include "randombytes.h"

// Use PQClean ML-DSA-65 (Dilithium3) clean implementation
#include "../PQClean/crypto_sign/ml-dsa-65/clean/api.h"

static bool _initialized = false;

static u8 _sk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES] __attribute__((aligned(4)));
static u8 _pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES] __attribute__((aligned(4)));

bool dilithium_init(void)
{
	if (_initialized) return true;

	#define WD_TIMEOUT_LONG 30000
	wd_set_timeout(WD_TIMEOUT_LONG);
	wd_feed();
	usb_device_task();

	if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(_pk, _sk) != 0)
	{
		wd_set_timeout(300);
		return false;
	}

	_initialized = true;
	wd_set_timeout(300);
	return true;
}

u32 dilithium_signature_max_len(void)
{
	return (u32)PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;
}

bool dilithium_sign(const u8 *msg, u32 msg_len, u8 *sig_out, u32 *out_len, u32 *time_us)
{
	if (!_initialized && !dilithium_init())
		return false;

	size_t sig_len = 0;
	#define WD_TIMEOUT_LONG 30000
	wd_set_timeout(WD_TIMEOUT_LONG);
	wd_feed();
	usb_device_task();

	os_timer_t t0 = timer_get_time();
	int rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig_out, &sig_len,
		(const uint8_t *)msg, (size_t)msg_len, _sk);
	os_timer_t t1 = timer_get_time();

	if (out_len) *out_len = (u32)sig_len;
	if (time_us) *time_us = (u32)(t1 - t0);

	wd_feed();
	usb_device_task();
	wd_set_timeout(300);

	return (rc == 0);
}

bool dilithium_verify(const u8 *msg, u32 msg_len, const u8 *sig, u32 sig_len, u32 *time_us)
{
	if (!_initialized && !dilithium_init())
		return false;

	#define WD_TIMEOUT_LONG 30000
	wd_set_timeout(WD_TIMEOUT_LONG);
	wd_feed();
	usb_device_task();

	os_timer_t t0 = timer_get_time();
	int rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, (size_t)sig_len,
		(const uint8_t *)msg, (size_t)msg_len, _pk);
	os_timer_t t1 = timer_get_time();

	if (time_us) *time_us = (u32)(t1 - t0);

	wd_feed();
	usb_device_task();
	wd_set_timeout(300);

	return (rc == 0);
}



