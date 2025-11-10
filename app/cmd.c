#include "common.h"
#include "cmd.h"
#include "hardware.h"
#include "gpreg.h"
#include "gpio.h"
#include "wd.h"
#include "main.h"
#include "spi.h"
#include "time.h"
#include "sphincs.h"
#include "dilithium.h"
#include "kyber.h"
#include "tls_pqc.h"
#include "usb_device.h"

#include "version.h"

typedef struct _cmd_t {
    const char *text;
    bool (*pfunc)(const struct _cmd_t *cmd);
    bool (*pfunc_set)(const struct _cmd_t *cmd,  const char **pptext);
    const char *help;
} cmd_t;

static const cmd_t _CMD_TABLE[];

static const char *ERR_INVALID_PARAMETER = "invalid parameter";
static const char *ERR_MISSING_PARAMETER = "missing parameter";
static const char *ERR_ILLEGAL_PARAMETER = "illegal parameter";
static const char *ERR_UNKNOWN_COMMAND   = "unknown command";

#define _PIN_STATE(pin) ((pin) ? 1 : 0)

static bool _pwr_state = true;

static void _cmd_error(const char *msg)
{
    OS_PRINTF("ERROR: %s" NL, msg);
}

static void _skip_spaces(const char **pptext)
{
    while (**pptext == ' ')
    {
        (*pptext)++;
    }
}

static bool _isdigit(char ch)
{
    return (((ch >= '0') && (ch <= '9')) ? true : false);
}

char *parse_number(s32 *number, const char *s)
{
    char *p;
    s32 tmp = 0;

    p = (char *) s;

    if (*p == '-')
    {
        p++;
    }
    if (_isdigit(*p) == 0)
    {
        return (NULL);
    }
    while (_isdigit(*p))
    {
        tmp *= 10;
        tmp += *p - '0';
        p++;
    }
    if (*s == '-')
    {
        *number = 0-tmp;
    }
    else
    {
        *number = tmp;
    }

    return p;
}

static bool _cmd_fetch_bool(bool *dest, const char **pptext)
{
    char ch = **pptext;
    if (ch == '0')
    {
        *dest = false;
    }
    else if (ch == '1')
    {
        *dest = true;
    }
    else
    {
        return (false);
    }
    (*pptext)++;
    return (true);
}

static bool _cmd_fetch_num(s32 *dest, const char **pptext)
{
    char *p;
    s32 num;

    if ((p = parse_number(&num, *pptext)) == NULL)
    {
        return (false);
    }

    *pptext = p;
    *dest = num;
    return (true);
}

static bool _cmd_fetch_hex(u8 *dest, const char **pptext)
{
    if (hex_to_bin(dest, *pptext, 1) != 1)
        return (false);

    (*pptext) += 2;
    return (true);
}

static bool _cmd_fetch_next(const char **pptext)
{
    _skip_spaces(pptext);

    if (**pptext != ',')
        return (false);

    (*pptext)++;
    return (true);
}

static bool _cmd_help(const cmd_t *cmd)
{
    const cmd_t *table = _CMD_TABLE;
    int i;

    OS_PRINTF("Tropicsquare USB/SPI interface" NL);
    OS_PRINTF("STM32 accepts named commands only; raw hex pass-through is disabled" NL);
    OS_PRINTF("Supported commands:" NL);

    for (i = 0; ; i++)
    {
        if (table[i].text == NULL)
            break;

        if ((table[i].help == NULL)
         || (strlen(table[i].help) == 0))
            continue;

        if (strlen(table[i].text) == 0)
            break;

        OS_PRINTF("%s : %s" NL, table[i].text, table[i].help);
    }
    return (true);
}
static bool _cmd_sphincs(const cmd_t *cmd)
{
    OS_PRINTF("%s: use SPHINCS <text> to sign\n", cmd->text);
    return (true);
}

static bool _cmd_dilithium(const cmd_t *cmd)
{
	OS_PRINTF("%s: use DILITHIUM <text> to sign\n", cmd->text);
	return (true);
}

static bool _cmd_verify(const cmd_t *cmd)
{
    OS_PRINTF("%s: use VERIFY <text> to sign and verify, timing both\n", cmd->text);
    return (true);
}

static bool _cmd_verify_set(const struct _cmd_t *cmd, const char **pptext)
{
    const char *text = *pptext;
    u32 text_len;

    while (*text == ' ') text++;
    text_len = (u32)strlen(text);
    if (text_len == 0)
    {
        _cmd_error(ERR_MISSING_PARAMETER);
        return (false);
    }

    if (! sphincs_init())
    {
        _cmd_error("SPHINCS not available");
        return (false);
    }

    u32 sig_max = sphincs_signature_max_len();
    if (sig_max == 0)
    {
        _cmd_error("SPHINCS init failed");
        return (false);
    }

    #define SPHINCS_MAX_SIG_LEN 17088
    static u8 sig_buffer[SPHINCS_MAX_SIG_LEN];
    if (sig_max > SPHINCS_MAX_SIG_LEN)
    {
        _cmd_error("signature too large for buffer");
        return (false);
    }

    u32 sig_len = 0;
    u32 sign_us = 0;
    if (! sphincs_sign((const u8 *)text, text_len, sig_buffer, &sig_len, &sign_us))
    {
        _cmd_error("sign failed");
        return (false);
    }

    u32 verify_us = 0;
    bool ok = sphincs_verify((const u8 *)text, text_len, sig_buffer, sig_len, &verify_us);
    OS_PRINTF("VERIFY: %s, sign_us=%lu, verify_us=%lu" NL, ok ? "OK" : "FAIL",
              (unsigned long)sign_us, (unsigned long)verify_us);
    return ok;
}

static bool _cmd_dilithium_set(const struct _cmd_t *cmd, const char **pptext)
{
	const char *text = *pptext;
	u32 text_len;

	while (*text == ' ') text++;
	text_len = (u32)strlen(text);
	if (text_len == 0)
	{
		_cmd_error(ERR_MISSING_PARAMETER);
		return (false);
	}

	if (! dilithium_init())
	{
		_cmd_error("DILITHIUM not available");
		return (false);
	}

	u32 sig_max = dilithium_signature_max_len();
	if (sig_max == 0)
	{
		_cmd_error("DILITHIUM init failed");
		return (false);
	}

	#define DILITHIUM_MAX_SIG_LEN 5000
	static u8 sig_buffer[DILITHIUM_MAX_SIG_LEN];
	if (sig_max > DILITHIUM_MAX_SIG_LEN)
	{
		_cmd_error("signature too large for buffer");
		return (false);
	}

	u32 sig_len = 0;
	u32 time_us = 0;
	bool ok = dilithium_sign((const u8 *)text, text_len, sig_buffer, &sig_len, &time_us);
	if (! ok)
	{
		_cmd_error("sign failed");
		return (false);
	}

	OS_PRINTF("%s: ", cmd->text);
	for (u32 i = 0; i < sig_len; i++)
	{
		OS_PRINTF("%02X", sig_buffer[i]);
	}
	OS_PRINTF(NL);
	OS_PRINTF("TIME_US: %lu" NL, (unsigned long)time_us);
	return (true);
}
static bool _cmd_shard(const cmd_t *cmd)
{
    OS_PRINTF("%s: use SHARD <text> to run 100 signs and time it\n", cmd->text);
    return (true);
}

static bool _cmd_kyber(const cmd_t *cmd)
{
	OS_PRINTF("%s: use KYBER <text> to encapsulate/decapsulate and print times\n", cmd->text);
	return (true);
}

static bool _cmd_kyber_set(const struct _cmd_t *cmd, const char **pptext)
{
	const char *text = *pptext;
	// Parameter accepted but not used; mirrors SPHINCS free-form style
	(void)text;

	if (! kyber_init())
	{
		_cmd_error("KYBER not available");
		return (false);
	}

	const u32 ct_len = kyber_ciphertext_len();
	const u32 ss_len = kyber_sharedsecret_len();
	static u8 ct_buffer[1536];
	static u8 ss1[64];
	static u8 ss2[64];
	if (ct_len > sizeof(ct_buffer) || ss_len > sizeof(ss1))
	{
		_cmd_error("buffer too small");
		return (false);
	}

	u32 enc_us = 0;
	if (! kyber_encapsulate(ct_buffer, ss1, &enc_us))
	{
		_cmd_error("encapsulate failed");
		return (false);
	}

	u32 dec_us = 0;
	if (! kyber_decapsulate(ct_buffer, ss2, &dec_us))
	{
		_cmd_error("decapsulate failed");
		return (false);
	}

	bool ok = (memcmp(ss1, ss2, ss_len) == 0);

	OS_PRINTF("KYBER: ");
	for (u32 i = 0; i < ct_len; i++)
	{
		OS_PRINTF("%02X", ct_buffer[i]);
	}
	OS_PRINTF(NL);
	OS_PRINTF("VERIFY: %s, enc_us=%lu, dec_us=%lu" NL, ok ? "OK" : "FAIL",
		(unsigned long)enc_us, (unsigned long)dec_us);
	return ok;
}

static bool _cmd_tls(const cmd_t *cmd)
{
	/* Don't print help message - it would be forwarded by USB bridge and corrupt TLS stream */
	/* Use "TLS=" or "TLS " to start handshake */
	/* OS_PRINTF("%s: perform TLS 1.3 handshake over USB (ML-KEM-768)\n", cmd->text); */
	return (true);
}

static bool _cmd_tls_set(const struct _cmd_t *cmd, const char **pptext)
{
	(void)cmd;
	(void)pptext;
	/* tls_pqc_handshake() will print the status message itself */
	/* Don't print here to avoid interfering with TLS data stream */
	return tls_pqc_handshake();
}

static bool _cmd_shard_set(const struct _cmd_t *cmd, const char **pptext)
{
    const char *text = *pptext;
    u32 text_len;

    while (*text == ' ') text++;
    text_len = (u32)strlen(text);
    if (text_len == 0)
    {
        _cmd_error(ERR_MISSING_PARAMETER);
        return (false);
    }

    if (! sphincs_init())
    {
        _cmd_error("SPHINCS not available");
        return (false);
    }

    u32 sig_max = sphincs_signature_max_len();
    if (sig_max == 0)
    {
        _cmd_error("SPHINCS init failed");
        return (false);
    }

    #define SPHINCS_MAX_SIG_LEN 17088
    static u8 sig_buffer[SPHINCS_MAX_SIG_LEN];
    if (sig_max > SPHINCS_MAX_SIG_LEN)
    {
        _cmd_error("signature too large for buffer");
        return (false);
    }

    const u32 runs = 100;
    u32 sig_len = 0;
    os_timer_t t0 = timer_get_time();
    for (u32 i = 0; i < runs; i++)
    {
        u32 iter_us = 0;
        if (! sphincs_sign((const u8 *)text, text_len, sig_buffer, &sig_len, &iter_us))
        {
            _cmd_error("sign failed");
            return (false);
        }
        OS_PRINTF("SHARD: %lu/%lu, us=%lu" NL, (unsigned long)(i+1), (unsigned long)runs, (unsigned long)iter_us);
        wd_feed();
        usb_device_task();
    }
    os_timer_t t1 = timer_get_time();
    u32 elapsed_us = (u32)(t1 - t0);
    u32 seconds = elapsed_us / (1000 * TIMER_MS);

    OS_PRINTF("%s: runs=%lu, seconds=%lu" NL, cmd->text, (unsigned long)runs, (unsigned long)seconds);
    return (true);
}

static bool _cmd_sphincs_set(const struct _cmd_t *cmd, const char **pptext)
{
    const char *text = *pptext;
    u32 text_len;

    OS_PRINTF("DBG: SPHINCS command start" NL);

    // Trim leading spaces (already skipped by dispatcher in most cases)
    while (*text == ' ') text++;
    text_len = (u32)strlen(text);
    OS_PRINTF("DBG: text_len=%lu" NL, (unsigned long)text_len);
    if (text_len == 0)
    {
        _cmd_error(ERR_MISSING_PARAMETER);
        return (false);
    }

    OS_PRINTF("DBG: calling sphincs_init()" NL);
    if (! sphincs_init())
    {
        _cmd_error("SPHINCS not available");
        return (false);
    }
    OS_PRINTF("DBG: sphincs_init() OK" NL);

    OS_PRINTF("DBG: getting signature max len" NL);
    u32 sig_max = sphincs_signature_max_len();
    OS_PRINTF("DBG: sig_max=%lu" NL, (unsigned long)sig_max);
    if (sig_max == 0)
    {
        _cmd_error("SPHINCS init failed");
        return (false);
    }

    // Use static buffer instead of malloc to avoid heap exhaustion
    // SPHINCS+-SHA2-128f-simple signature is 17088 bytes max
    #define SPHINCS_MAX_SIG_LEN 17088
    static u8 sig_buffer[SPHINCS_MAX_SIG_LEN];
    
    if (sig_max > SPHINCS_MAX_SIG_LEN)
    {
        _cmd_error("signature too large for buffer");
        return (false);
    }

    OS_PRINTF("DBG: calling sphincs_sign()" NL);
    u32 sig_len = 0;
    u32 time_us = 0;
    bool ok = sphincs_sign((const u8 *)text, text_len, sig_buffer, &sig_len, &time_us);
    OS_PRINTF("DBG: sphincs_sign() returned, ok=%d" NL, ok ? 1 : 0);
    if (! ok)
    {
        _cmd_error("sign failed");
        return (false);
    }

    OS_PRINTF("DBG: sign OK, sig_len=%lu, time_us=%lu" NL, (unsigned long)sig_len, (unsigned long)time_us);

    // Print hex signature
    OS_PRINTF("%s: ", cmd->text);
    OS_PRINTF("DBG: printing signature hex..." NL);
    for (u32 i = 0; i < sig_len; i++)
    {
        OS_PRINTF("%02X", sig_buffer[i]);
        // Progress indicator every 1KB
        if ((i > 0) && ((i % 1024) == 0))
        {
            OS_PRINTF("\nDBG: progress %lu/%lu" NL, (unsigned long)i, (unsigned long)sig_len);
        }
    }
    OS_PRINTF(NL);
    OS_PRINTF("TIME_US: %lu" NL, (unsigned long)time_us);
    OS_PRINTF("DBG: SPHINCS command complete" NL);

    return (true);
}

static void _cmd_basic_reply(const cmd_t *cmd)
{
    OS_PRINTF("%s: ", cmd->text);
}

static bool _cmd_auto(const cmd_t *cmd)
{
    _cmd_basic_reply(cmd);
    if (main_spi_auto)
        OS_PRINTF("1, %02X, %02X" NL, main_spi_get_resp, main_spi_no_resp);
    else
       OS_PRINTF("0" NL);
    return (true);
}

static bool _cmd_auto_set(const struct _cmd_t *cmd, const char **pptext)
{
  #define MSG_HDR_GET_RESP     (0xAA)
  #define MSG_VALUE_NO_RESP    (0xFF)

    bool state;
    u8 get_resp = MSG_HDR_GET_RESP;
    u8 no_resp  = MSG_VALUE_NO_RESP;
    
    if (! _cmd_fetch_bool(&state, pptext))
    {
        goto err;
    }
    if (_cmd_fetch_next(pptext))
    {   // second parameter may be GET_RESP value
        if (! _cmd_fetch_hex(&get_resp, pptext))
            goto err;

    }
    if (_cmd_fetch_next(pptext))
    {   // thitd parameter may be NO_RESP value
        if (! _cmd_fetch_hex(&no_resp, pptext))
            goto err;
    }
    main_spi_auto     = state;
    main_spi_get_resp = get_resp;
    main_spi_no_resp  = no_resp;
    // OS_PRINTF("[%02x, %02x]", get_resp, no_resp);
    return (true);

err:
    _cmd_error(ERR_INVALID_PARAMETER);
    return (false);
}

#ifdef HW_BUTTON_PRESSED
static bool _cmd_button(const cmd_t *cmd)
{
    _cmd_basic_reply(cmd);
    
    if (HW_BUTTON_PRESSED)
        OS_PRINTF("1" NL);
    else
        OS_PRINTF("0" NL);

    return (true);
}
#endif // defined HW_BUTTON_PRESSED

static bool _cmd_cs(const cmd_t *cmd)
{
    _cmd_basic_reply(cmd);
    OS_PRINTF("%u" NL, (spi1_cs_state() == SPI_CS_ACTIVE) ? 1 : 0); // "1" == CS active (LOW)
    return (true);
}

static bool _cmd_cs_set(const struct _cmd_t *cmd, const char **pptext)
{
    bool state;
    
    if (! _cmd_fetch_bool(&state, pptext))
    {
        _cmd_error(ERR_INVALID_PARAMETER);
        return (false);
    }

    spi1_cs(state ? SPI_CS_ACTIVE : SPI_CS_IDLE);
    return (true);
}

static bool _cmd_clkdiv(const cmd_t *cmd)
{
    _cmd_basic_reply(cmd);
    OS_PRINTF("%lu" NL, spi1_get_prescaler());
    return (true);
}

static bool _cmd_clkdiv_set(const struct _cmd_t *cmd, const char **pptext)
{
    s32 value;

    if (! _cmd_fetch_num(&value, pptext))
    {
        goto err;
    }

    if (spi1_set_prescaler(value))
        return (true);

err:
    _cmd_error(ERR_INVALID_PARAMETER);
    return (false);
}

static bool _cmd_id(const cmd_t *cmd)
{
    _cmd_basic_reply(cmd);
    OS_PRINTF(VERSION_NAME NL);
    return (true);
}

char *ux_device_sn_text(void);

static bool _cmd_sn(const cmd_t *cmd)
{
    _cmd_basic_reply(cmd);
    OS_PRINTF("%s", ux_device_sn_text());
    OS_PRINTF(NL);
    return (true);
}

static bool _cmd_ver(const cmd_t *cmd)
{
    _cmd_basic_reply(cmd);
    OS_PRINTF("FW %s, HW %s, https://github.com/tropicsquare" NL, VERSION_STRING, HW_NAME);
    return (true);
}

static bool _cmd_reset(const cmd_t *cmd)
{
    OS_PRINTF("RESET" NL);
    OS_DELAY(10);
    wd_reset(GPREG_BOOT_REBOOT);
    return (true);
}

static bool _cmd_gpo(const cmd_t *cmd)
{
    _cmd_basic_reply(cmd);
    OS_PRINTF("%d" NL, _PIN_STATE(HW_GPO_IN));
    return (true);
}

static bool _cmd_pwr(const cmd_t *cmd)
{
    _cmd_basic_reply(cmd);
    OS_PRINTF("%d" NL, _pwr_state ? 1 : 0);
    return (true);
}

static bool _cmd_pwr_set(const struct _cmd_t *cmd,  const char **pptext)
{
    bool state;
    
    if (! _cmd_fetch_bool(&state, pptext))
    {
        _cmd_error(ERR_INVALID_PARAMETER);
        return (false);
    }

    if (state)
    {
        HW_CHIP_PWR_ON; 
        HW_SPI_OE_ENABLE;
    }
    else
    {
        HW_CHIP_PWR_OFF;
        HW_SPI_OE_DISABLE; // also disconnect SPI interface (if possible)
    }
    _pwr_state = state;
    return (true);
}

static const cmd_t *_find_cmd(const cmd_t *table, const char **text)
{
    uint16_t i, l;

    for (i = 0; ; i++)
    {
        if (table[i].text == NULL)
            return (NULL);

        if ((l = strlen(table[i].text)) == 0)
            return (NULL);

        if (strnicmp(*text, table[i].text, l) == 0)
        {   // text found
            // now next character should be OK
            if (! is_char((*text)[l]))
            {
                (*text) += l;
                return (&table[i]);
            }
        }
    }
    return (NULL);
}

static bool _process_cmd(const cmd_t *cmd, const char **pptext)
{
    _skip_spaces(pptext);

    if (**pptext == '=')
    {   // parameter included
        if (cmd->pfunc_set == NULL)
        {   // but not enabled for this command
            _cmd_error(ERR_INVALID_PARAMETER);
            return (false);
        }
        (*pptext)++;
        _skip_spaces(pptext);
        return (cmd->pfunc_set(cmd, pptext));
    }
    else if ((**pptext != '?') && (**pptext != '\0'))
    {   // allow free-form parameter (space-separated) for handlers that accept it via pfunc_set
        if (cmd->pfunc_set != NULL)
        {
            return (cmd->pfunc_set(cmd, pptext));
        }
        _cmd_error(ERR_ILLEGAL_PARAMETER);
        return (false);
    }

    // parameter not included
    if (cmd->pfunc == NULL)
    {   // but parameter required
        _cmd_error(ERR_MISSING_PARAMETER);
        return (false);
    }

    return (cmd->pfunc(cmd));
}

void cmd_parse(const char *ptext)
{
    const cmd_t *cmd;

    if (*ptext == '#')
        return; // quietly skip remarks

    if ((cmd = _find_cmd(_CMD_TABLE, &ptext)) == NULL)
    {
        _cmd_error(ERR_UNKNOWN_COMMAND);
        return;
    }
    
    if (! _process_cmd(cmd, &ptext))
    {
        return;
    }
    OS_PRINTF("OK" NL);
}

static const cmd_t _CMD_TABLE[] = {
    {"AUTO",      _cmd_auto,    _cmd_auto_set,  "Automatic response reading get/set"},
#ifdef HW_BUTTON_PRESSED
    {"BUTTON",    _cmd_button,  NULL,           "Get button state"},
#endif // defined HW_BUTTON_PRESSED
    {"CLKDIV",    _cmd_clkdiv,  _cmd_clkdiv_set,"Clock divisor get/set"},
    {"CS",        _cmd_cs,      _cmd_cs_set,    "SPI chip select direct control"},
    {"GPO",       _cmd_gpo,     NULL,           "Show GPO state"},
    {"HELP",      _cmd_help,    NULL,           "This help text"},
    {"ID",        _cmd_id,      NULL,           "Request product id"},
    {"PWR",       _cmd_pwr,     _cmd_pwr_set,   "Get/set target power"},
    {"RESET",     _cmd_reset,   NULL,           "Instant reset"},
    {"SPHINCS",   _cmd_sphincs, _cmd_sphincs_set, "Sign text with SPHINCS+ and report time"},
    {"DILITHIUM", _cmd_dilithium, _cmd_dilithium_set, "Sign text with Dilithium and report time"},
    {"KYBER",     _cmd_kyber,   _cmd_kyber_set,  "Kyber768 KEM encap/decap and print times"},
	{"TLS",       _cmd_tls,     _cmd_tls_set,    "TLS 1.3 handshake over USB (ML-KEM-768)"},
    {"VERIFY",    _cmd_verify,  _cmd_verify_set, "Sign then verify; print times"},
    {"SHARD",      _cmd_shard,  _cmd_shard_set,  "Run 100 SPHINCS+ signs and print total seconds"},
    {"SN",        _cmd_sn,      NULL,           "Request product serial number"},
    {"VER",       _cmd_ver,     NULL,           "Request version information"},

    {NULL, NULL, 0, NULL} // command list termination
};

