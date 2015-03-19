/* Copyright 2015 Peter Hater
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * This file implements the schannel provider, or, the SSL/TLS implementations.
 */

#include "config.h"
#include "wine/port.h"

#ifdef __REACTOS__
#include <precomp.h>
#include <strsafe.h>
#else
#include <errno.h>
#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "sspi.h"
#include "schannel.h"
#include "wine/debug.h"
#endif

#include "secur32_priv.h"

#include <polarssl/config.h>
#include <polarssl/net.h>
#include <polarssl/ssl.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/certs.h>
#include <polarssl/x509.h>
#include <polarssl/error.h>
#include <polarssl/debug.h>

#ifdef __REACTOS__
#define __wine_dbch_secur32 __wine_dbch_schannel
static HMODULE polarssl_handle;
#else
#include "wine/library.h"
WINE_DEFAULT_DEBUG_CHANNEL(secur32);
WINE_DECLARE_DEBUG_CHANNEL(winediag);
static void *polarssl_handle;
#endif

typedef struct
{
    ssl_context ssl;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    struct schan_transport *transport;
} POLARSSL_SESSION, *PPOLARSSL_SESSION;

#if defined(__REACTOS__) && defined(_MSC_VER)
#include <msvc_typeof_hack_polar.h>
#endif

#define MAKE_FUNCPTR(f) static typeof(f) * p##f
MAKE_FUNCPTR(ssl_init);
MAKE_FUNCPTR(ssl_free);
MAKE_FUNCPTR(ssl_set_endpoint);
MAKE_FUNCPTR(ssl_set_authmode);
MAKE_FUNCPTR(ssl_set_hostname);
MAKE_FUNCPTR(ssl_set_renegotiation);
MAKE_FUNCPTR(ssl_set_min_version);
MAKE_FUNCPTR(ssl_set_max_version);
MAKE_FUNCPTR(ssl_set_ca_chain);
MAKE_FUNCPTR(ssl_set_rng);
MAKE_FUNCPTR(ssl_set_bio);
MAKE_FUNCPTR(ssl_set_verify);
MAKE_FUNCPTR(ssl_get_peer_cert);
MAKE_FUNCPTR(ssl_get_verify_result);
MAKE_FUNCPTR(ssl_get_bytes_avail);
MAKE_FUNCPTR(ssl_get_version);
MAKE_FUNCPTR(ssl_get_ciphersuite);
MAKE_FUNCPTR(ssl_get_ciphersuite_id);
MAKE_FUNCPTR(ssl_ciphersuite_from_id);
MAKE_FUNCPTR(ssl_handshake);
MAKE_FUNCPTR(ssl_read);
MAKE_FUNCPTR(ssl_write);
MAKE_FUNCPTR(ssl_close_notify);
MAKE_FUNCPTR(ssl_set_dbg);
MAKE_FUNCPTR(debug_set_threshold);
MAKE_FUNCPTR(x509_crt_init);
MAKE_FUNCPTR(x509_crt_free);
MAKE_FUNCPTR(x509_crt_parse);
MAKE_FUNCPTR(x509_crt_info);
MAKE_FUNCPTR(ctr_drbg_init);
MAKE_FUNCPTR(ctr_drbg_free);
MAKE_FUNCPTR(ctr_drbg_random);
MAKE_FUNCPTR(entropy_init);
MAKE_FUNCPTR(entropy_free);
MAKE_FUNCPTR(entropy_func);
#undef MAKE_FUNCPTR

static int schan_pull_adapter(void *t, unsigned char *buff, size_t buff_len)
{
    struct schan_transport *transport = (struct schan_transport *)t;
    int ret;

    TRACE("POLARSSL %p %p %u\n", t, buff, buff_len);

    ret = schan_pull(transport, buff, &buff_len);
    if (ret == EAGAIN)
    {
        TRACE("Can't read data from SSL without blocking\n");
        return POLARSSL_ERR_NET_WANT_READ;
    }
    if (ret)
    {
        ERR("Error pulling data from SSL %d\n", ret);
        return -1;
    }

    return buff_len;
}

static int schan_push_adapter(void *t, const unsigned char *buff, size_t buff_len)
{
    struct schan_transport *transport = (struct schan_transport *)t;
    int ret;

    TRACE("POLARSSL %p %p %u\n", t, buff, buff_len);

    ret = schan_push(transport, buff, &buff_len);
    if (ret == EAGAIN)
    {
        TRACE("Can't write data to SSL without blocking\n");
        return POLARSSL_ERR_NET_WANT_WRITE;
    }
    if (ret)
    {
        ERR("Error pushing data to SSL %d\n", ret);
        return -1;
    }

    return buff_len;
}

DWORD schan_imp_enabled_protocols(void)
{
    /* NOTE: No support for SSL 2.0 */
    TRACE("POLARSSL\n");

    return 0
#ifdef POLARSSL_SSL_PROTO_SSL3
        | SP_PROT_SSL3_CLIENT | SP_PROT_SSL3_SERVER
#endif
#ifdef POLARSSL_SSL_PROTO_TLS1
        | SP_PROT_TLS1_0_CLIENT | SP_PROT_TLS1_SERVER
#endif
#ifdef POLARSSL_SSL_PROTO_TLS1_1
        | SP_PROT_TLS1_1_CLIENT
#endif
#ifdef POLARSSL_SSL_PROTO_TLS1_2
        | SP_PROT_TLS1_2_CLIENT
#endif
        ;
}

static void schan_polarssl_log(void *ctx, int level, const char *msg)
{
    int len = strlen(msg);
    TRACE("POLARSSL <%d> %s%s", level, msg, (!len || msg[len-1] != '\n') ? "\n" : "");
}

static int schan_verify(void *data, x509_crt *crt, int depth, int *flags)
{
    char buf[1024];
    int crt_flags = *flags;

    ((void) data);

    TRACE("Verify requested for (Depth %d):\n", depth);
    px509_crt_info(buf, sizeof(buf) - 1, "", crt);
    TRACE("%s\n", buf);

    if (crt_flags & BADCERT_EXPIRED)
        TRACE(" ! server certificate has expired\n");
    if (crt_flags & BADCERT_REVOKED)
        TRACE(" ! server certificate has been revoked\n");
    if (crt_flags & BADCERT_CN_MISMATCH)
        TRACE(" ! CN mismatch\n");
    if (crt_flags & BADCERT_NOT_TRUSTED)
        TRACE(" ! self-signed or not signed by a trusted CA\n");
    if (crt_flags & BADCRL_NOT_TRUSTED)
        TRACE(" ! CRL not trusted\n");
    if (crt_flags & BADCRL_EXPIRED)
        TRACE(" ! CRL expired\n");
    if (crt_flags & BADCERT_OTHER)
        TRACE(" ! other (unknown) flag\n");
    if (crt_flags == 0)
        TRACE(" This certificate has no flags\n");

    return 0 ;
}

BOOL schan_imp_create_session(schan_imp_session *session, schan_credentials *cred)
{
    POLARSSL_SESSION *s;
    int ret;

    TRACE("POLARSSL %p %p %p\n", session, *session, cred);

    s = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(POLARSSL_SESSION));
    if (!(*session = (schan_imp_session)s))
    {
        ERR("Not enough memory to create session\n");
        return FALSE;
    }

    TRACE("POLARSSL init entropy\n");
    pentropy_init(&s->entropy);

    FIXME("POLARSSL init random - change static entropy private data\n");
    ret = pctr_drbg_init(&s->ctr_drbg, pentropy_func, &s->entropy,
                         (const unsigned char *)"PolarSSL", 8);
    if (ret != 0)
    {
        ERR("ctr_drbg_init failed with -%x\n", -ret);
        pentropy_free(&s->entropy);
        HeapFree(GetProcessHeap(), 0, s);
        return FALSE;
    }

    TRACE("POLARSSL init ssl\n");
    ret = pssl_init(&s->ssl);
    if (ret != 0)
    {
        ERR("ssl_init failed with -%x\n", -ret);
        pctr_drbg_free(&s->ctr_drbg);
        pentropy_free(&s->entropy);
        HeapFree(GetProcessHeap(), 0, s);
        return FALSE;
    }

    TRACE("POLARSSL set dbg\n");
    pssl_set_dbg(&s->ssl, schan_polarssl_log, stdout);

    TRACE("POLARSSL set endpoint %d\n", cred->credential_use);
    pssl_set_endpoint(&s->ssl, (cred->credential_use & SECPKG_CRED_INBOUND) ? SSL_IS_SERVER : SSL_IS_CLIENT);

    TRACE("POLARSSL set authmode\n");
    pssl_set_authmode(&s->ssl, SSL_VERIFY_OPTIONAL);

    TRACE("POLARSSL parse certificate %p\n", cred->credentials);
    if (cred->credentials)
    {
        /*x509_crt cacert;
        ret = px509_crt_parse(&cacert, (const unsigned char *)cred->credentials,
                              strlen((const char *)cred->credentials));
        if (ret < 0)
        {
            ERR("Loading the CA root certificate failed! x509_crt_parse returned -0x%x", -ret);
            pctr_drbg_free(&s->ctr_drbg);
            pentropy_free(&s->entropy);
            pssl_free(&s->ssl);
            HeapFree(GetProcessHeap(), 0, s);
            return FALSE;
        }*/
        TRACE("POLARSSL set server ca chain\n");
        pssl_set_ca_chain(&s->ssl, (x509_crt *)cred->credentials, NULL,
            (cred->credential_use & SECPKG_CRED_INBOUND) ? "PolarSSL Server" : "PolarSSL client" );
    }

    TRACE("POLARSSL set rng\n");
    pssl_set_rng(&s->ssl, pctr_drbg_random, &s->ctr_drbg);

    TRACE("POLARSSL set verify\n");
    pssl_set_verify(&s->ssl, schan_verify, NULL);

    TRACE("POLARSSL set versions\n");
    pssl_set_min_version(&s->ssl, SSL_MIN_MAJOR_VERSION, SSL_MIN_MINOR_VERSION);
    pssl_set_max_version(&s->ssl, SSL_MAX_MAJOR_VERSION, SSL_MAX_MINOR_VERSION);

    return TRUE;
}

void schan_imp_dispose_session(schan_imp_session session)
{
    POLARSSL_SESSION *s = (POLARSSL_SESSION *)session;

    TRACE("POLARSSL %p\n", session);

    pssl_close_notify(&s->ssl);
    pctr_drbg_free(&s->ctr_drbg);
    pentropy_free(&s->entropy);
    pssl_free(&s->ssl);

    HeapFree(GetProcessHeap(), 0, s);
}

void schan_imp_set_session_transport(schan_imp_session session,
                                     struct schan_transport *t)
{
    POLARSSL_SESSION *s = (POLARSSL_SESSION *)session;
    TRACE("POLARSSL %p %p %d\n", session, t, s->ssl.state);

    s->transport = t;
    pssl_set_bio(&s->ssl, schan_pull_adapter, t, schan_push_adapter, t);
}

void schan_imp_set_session_target(schan_imp_session session, const char *target)
{
    POLARSSL_SESSION *s = (POLARSSL_SESSION *)session;
    TRACE("POLARSSL %p %p %d\n", session, target, s->ssl.state);

    pssl_set_hostname( &s->ssl, target );
}

SECURITY_STATUS schan_imp_handshake(schan_imp_session session)
{
    POLARSSL_SESSION *s = (POLARSSL_SESSION *)session;
    int err;

    TRACE("POLARSSL %p %d\n", session, s->ssl.state);

    err = pssl_handshake(&s->ssl);

    if (err == POLARSSL_ERR_NET_WANT_READ ||
        err == POLARSSL_ERR_NET_WANT_WRITE)
    {
        TRACE("Continue...\n");
        return SEC_I_CONTINUE_NEEDED;
    }
    if (err == POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE)
    {
        ERR("SSL Feature unavailable...\n");
        return SEC_E_UNSUPPORTED_FUNCTION;
    }
    if (err != 0)
    {
        ERR("Unknown code -%x...\n", -err);
        return SEC_E_INTERNAL_ERROR;
    }

    TRACE("Handshake completed\n");
    TRACE("Protocol is %s, Cipher suite is %s\n", pssl_get_version(&s->ssl), pssl_get_ciphersuite(&s->ssl));
    return SEC_E_OK;
}


static unsigned int schannel_get_cipher_block_size(int ciphersuite_id)
{
    const ssl_ciphersuite_t *cipher_suite = pssl_ciphersuite_from_id(ciphersuite_id);
    const struct
    {
        int algo;
        unsigned int size;
    }
    algorithms[] =
    {
        {POLARSSL_CIPHER_NONE,                   1},
        {POLARSSL_CIPHER_NULL,                   1},
    #ifdef POLARSSL_AES_C
        {POLARSSL_CIPHER_AES_128_ECB,           16},
        {POLARSSL_CIPHER_AES_192_ECB,           16},
        {POLARSSL_CIPHER_AES_256_ECB,           16},
        {POLARSSL_CIPHER_AES_128_CBC,           16},
        {POLARSSL_CIPHER_AES_192_CBC,           16},
        {POLARSSL_CIPHER_AES_256_CBC,           16},
        {POLARSSL_CIPHER_AES_128_CFB128,        16},
        {POLARSSL_CIPHER_AES_192_CFB128,        16},
        {POLARSSL_CIPHER_AES_256_CFB128,        16},
        {POLARSSL_CIPHER_AES_128_CTR,           16},
        {POLARSSL_CIPHER_AES_192_CTR,           16},
        {POLARSSL_CIPHER_AES_256_CTR,           16},
        {POLARSSL_CIPHER_AES_128_GCM,           16},
        {POLARSSL_CIPHER_AES_192_GCM,           16},
        {POLARSSL_CIPHER_AES_256_GCM,           16},
    #endif
    #ifdef POLARSSL_CAMELLIA_C
        {POLARSSL_CIPHER_CAMELLIA_128_ECB,      16},
        {POLARSSL_CIPHER_CAMELLIA_192_ECB,      16},
        {POLARSSL_CIPHER_CAMELLIA_256_ECB,      16},
        {POLARSSL_CIPHER_CAMELLIA_128_CBC,      16},
        {POLARSSL_CIPHER_CAMELLIA_192_CBC,      16},
        {POLARSSL_CIPHER_CAMELLIA_256_CBC,      16},
        {POLARSSL_CIPHER_CAMELLIA_128_CFB128,   16},
        {POLARSSL_CIPHER_CAMELLIA_192_CFB128,   16},
        {POLARSSL_CIPHER_CAMELLIA_256_CFB128,   16},
        {POLARSSL_CIPHER_CAMELLIA_128_CTR,      16},
        {POLARSSL_CIPHER_CAMELLIA_192_CTR,      16},
        {POLARSSL_CIPHER_CAMELLIA_256_CTR,      16},
        {POLARSSL_CIPHER_CAMELLIA_128_GCM,      16},
        {POLARSSL_CIPHER_CAMELLIA_192_GCM,      16},
        {POLARSSL_CIPHER_CAMELLIA_256_GCM,      16},
    #endif
    #ifdef POLARSSL_DES_C
        {POLARSSL_CIPHER_DES_ECB,                8},
        {POLARSSL_CIPHER_DES_CBC,                8},
        {POLARSSL_CIPHER_DES_EDE_ECB,            8},
        {POLARSSL_CIPHER_DES_EDE_CBC,            8},
        {POLARSSL_CIPHER_DES_EDE3_ECB,           8},
        {POLARSSL_CIPHER_DES_EDE3_CBC,           8},
    #endif
    #ifdef POLARSSL_BLOWFISH_C
        {POLARSSL_CIPHER_BLOWFISH_ECB,           8},
        {POLARSSL_CIPHER_BLOWFISH_CBC,           8},
        {POLARSSL_CIPHER_BLOWFISH_CFB64,         8},
        {POLARSSL_CIPHER_BLOWFISH_CTR,           8},
    #endif
    #ifdef POLARSSL_ARC4_C
        {POLARSSL_CIPHER_ARC4_128,               1},
    #endif
    #ifdef POLARSSL_CCM_C
        {POLARSSL_CIPHER_AES_128_CCM,           16},
        {POLARSSL_CIPHER_AES_192_CCM,           16},
        {POLARSSL_CIPHER_AES_256_CCM,           16},
        {POLARSSL_CIPHER_CAMELLIA_128_CCM,      16},
        {POLARSSL_CIPHER_CAMELLIA_192_CCM,      16},
        {POLARSSL_CIPHER_CAMELLIA_256_CCM,      16},
    #endif
    };

    int i;
    for (i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); i++)
    {
        if (algorithms[i].algo == cipher_suite->cipher)
            return algorithms[i].size;
    }

    FIXME("Unknown cipher %#x, returning 1\n", ciphersuite_id);
    return 1;
}

static unsigned int schannel_get_cipher_key_size(int ciphersuite_id)
{
    const ssl_ciphersuite_t *cipher_suite = pssl_ciphersuite_from_id(ciphersuite_id);
    const struct
    {
        int algo;
        unsigned int size;
    }
    algorithms[] =
    {
        {POLARSSL_CIPHER_NONE,                    0},
        {POLARSSL_CIPHER_NULL,                    0},
    #ifdef POLARSSL_AES_C
        {POLARSSL_CIPHER_AES_128_ECB,           128},
        {POLARSSL_CIPHER_AES_192_ECB,           192},
        {POLARSSL_CIPHER_AES_256_ECB,           256},
        {POLARSSL_CIPHER_AES_128_CBC,           128},
        {POLARSSL_CIPHER_AES_192_CBC,           192},
        {POLARSSL_CIPHER_AES_256_CBC,           256},
        {POLARSSL_CIPHER_AES_128_CFB128,        128},
        {POLARSSL_CIPHER_AES_192_CFB128,        192},
        {POLARSSL_CIPHER_AES_256_CFB128,        256},
        {POLARSSL_CIPHER_AES_128_CTR,           128},
        {POLARSSL_CIPHER_AES_192_CTR,           192},
        {POLARSSL_CIPHER_AES_256_CTR,           256},
        {POLARSSL_CIPHER_AES_128_GCM,           128},
        {POLARSSL_CIPHER_AES_192_GCM,           192},
        {POLARSSL_CIPHER_AES_256_GCM,           256},
    #endif
    #ifdef POLARSSL_CAMELLIA_C
        {POLARSSL_CIPHER_CAMELLIA_128_ECB,      128},
        {POLARSSL_CIPHER_CAMELLIA_192_ECB,      192},
        {POLARSSL_CIPHER_CAMELLIA_256_ECB,      256},
        {POLARSSL_CIPHER_CAMELLIA_128_CBC,      128},
        {POLARSSL_CIPHER_CAMELLIA_192_CBC,      192},
        {POLARSSL_CIPHER_CAMELLIA_256_CBC,      256},
        {POLARSSL_CIPHER_CAMELLIA_128_CFB128,   128},
        {POLARSSL_CIPHER_CAMELLIA_192_CFB128,   192},
        {POLARSSL_CIPHER_CAMELLIA_256_CFB128,   256},
        {POLARSSL_CIPHER_CAMELLIA_128_CTR,      128},
        {POLARSSL_CIPHER_CAMELLIA_192_CTR,      192},
        {POLARSSL_CIPHER_CAMELLIA_256_CTR,      256},
        {POLARSSL_CIPHER_CAMELLIA_128_GCM,      128},
        {POLARSSL_CIPHER_CAMELLIA_192_GCM,      192},
        {POLARSSL_CIPHER_CAMELLIA_256_GCM,      256},
    #endif
    #ifdef POLARSSL_DES_C
        {POLARSSL_CIPHER_DES_ECB,               56},
        {POLARSSL_CIPHER_DES_CBC,               56},
        {POLARSSL_CIPHER_DES_EDE_ECB,           56},
        {POLARSSL_CIPHER_DES_EDE_CBC,           56},
        {POLARSSL_CIPHER_DES_EDE3_ECB,          168},
        {POLARSSL_CIPHER_DES_EDE3_CBC,          168},
    #endif
    #ifdef POLARSSL_BLOWFISH_C
        /* FIXME: blowfish sizes??? */
        {POLARSSL_CIPHER_BLOWFISH_ECB,            0},
        {POLARSSL_CIPHER_BLOWFISH_CBC,            0},
        {POLARSSL_CIPHER_BLOWFISH_CFB64,          0},
        {POLARSSL_CIPHER_BLOWFISH_CTR,            0},
    #endif
    #ifdef POLARSSL_ARC4_C
        {POLARSSL_CIPHER_ARC4_128,              128},
    #endif
    #ifdef POLARSSL_CCM_C
        {POLARSSL_CIPHER_AES_128_CCM,           128},
        {POLARSSL_CIPHER_AES_192_CCM,           192},
        {POLARSSL_CIPHER_AES_256_CCM,           256},
        {POLARSSL_CIPHER_CAMELLIA_128_CCM,      128},
        {POLARSSL_CIPHER_CAMELLIA_192_CCM,      192},
        {POLARSSL_CIPHER_CAMELLIA_256_CCM,      256},
    #endif
    };
    int i;

    for (i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); i++)
    {
        if (algorithms[i].algo == cipher_suite->cipher)
            return algorithms[i].size;
    }

    FIXME("Unknown cipher %#x, returning 0\n", ciphersuite_id);
    return 0;
}

static unsigned int schannel_get_mac_key_size(int ciphersuite_id)
{
    const ssl_ciphersuite_t *cipher_suite = pssl_ciphersuite_from_id(ciphersuite_id);
    const unsigned int algorithms[] =
    {
        0,   // POLARSSL_MD_NONE
        128, // POLARSSL_MD_MD2
        56,  // POLARSSL_MD_MD4
        56,  // POLARSSL_MD_MD5
        56,  // POLARSSL_MD_SHA1
        56,  // POLARSSL_MD_SHA224
        168, // POLARSSL_MD_SHA256
        168, // POLARSSL_MD_SHA384
        128, // POLARSSL_MD_SHA512
        // FIXME: ripemd160 size ???
        0, // POLARSSL_MD_RIPEMD160
    };

    if (cipher_suite->mac >= 0 && cipher_suite->mac < sizeof(algorithms) / sizeof(algorithms[0]))
    {
        return algorithms[cipher_suite->mac];
    }

    FIXME("Unknown mac %#x for ciphersuite %#x, returning 0\n", cipher_suite->mac, ciphersuite_id);
    return 0;
}

static unsigned int schannel_get_kx_key_size(const ssl_context *ssl, int ciphersuite_id)
{
    const ssl_ciphersuite_t *cipher_suite = pssl_ciphersuite_from_id(ciphersuite_id);
    x509_crt *server_cert;

    /* FIXME: if we are server take ca_chain. if we are client take server cert (peer_cert) */
    server_cert = (ssl->endpoint == SSL_IS_SERVER) ? ssl->ca_chain : ssl->session->peer_cert;

    if (cipher_suite->key_exchange != POLARSSL_KEY_EXCHANGE_NONE)
        return server_cert->pk.pk_info->get_size(server_cert->pk.pk_ctx);

    FIXME("Unknown kx %#x, returning 0\n", cipher_suite->key_exchange);
    return 0;
}

static DWORD schannel_get_protocol(const ssl_context *ssl)
{
    // FIXME: currently schannel only implements client connections, but
    // there's no reason it couldn't be used for servers as well.  The
    // context doesn't tell us which it is, so decide based on ssl endpoint value.
    //
    switch (ssl->minor_ver)
    {
    case SSL_MINOR_VERSION_0: return (ssl->endpoint == SSL_IS_CLIENT) ? SP_PROT_SSL3_CLIENT : SP_PROT_SSL3_SERVER;
    case SSL_MINOR_VERSION_1: return (ssl->endpoint == SSL_IS_CLIENT) ? SP_PROT_TLS1_0_CLIENT : SP_PROT_TLS1_SERVER;
    case SSL_MINOR_VERSION_2: return (ssl->endpoint == SSL_IS_CLIENT) ? SP_PROT_TLS1_1_CLIENT : SP_PROT_TLS1_SERVER;
    case SSL_MINOR_VERSION_3: return (ssl->endpoint == SSL_IS_CLIENT) ? SP_PROT_TLS1_2_CLIENT : SP_PROT_TLS1_SERVER;
    default:
        FIXME("unknown protocol %d\n", ssl->minor_ver);
        return 0;
    }
}

static ALG_ID schannel_get_cipher_algid(int ciphersuite_id)
{
    const ssl_ciphersuite_t *cipher_suite = pssl_ciphersuite_from_id( ciphersuite_id );
    switch (cipher_suite->cipher)
    {
    case POLARSSL_CIPHER_NONE:
    case POLARSSL_CIPHER_NULL:
        return 0;

#ifdef POLARSSL_ARC4_C
    /* ARC4 */
    case POLARSSL_CIPHER_ARC4_128:
        return CALG_RC4;
#endif


#ifdef POLARSSL_DES_C
    /* DES */
    case POLARSSL_CIPHER_DES_ECB:
    case POLARSSL_CIPHER_DES_CBC:
    case POLARSSL_CIPHER_DES_EDE_ECB:
    case POLARSSL_CIPHER_DES_EDE_CBC:
        return CALG_DES;

    /* 3DES */
    case POLARSSL_CIPHER_DES_EDE3_ECB:
    case POLARSSL_CIPHER_DES_EDE3_CBC:
        return CALG_3DES;
#endif

#ifdef POLARSSL_AES_C

    /* AES 128 */
    case POLARSSL_CIPHER_AES_128_ECB:
    case POLARSSL_CIPHER_AES_128_CBC:
    case POLARSSL_CIPHER_AES_128_CFB128:
    case POLARSSL_CIPHER_AES_128_CTR:
    case POLARSSL_CIPHER_AES_128_GCM:
#ifdef POLARSSL_CCM_C
    case POLARSSL_CIPHER_AES_128_CCM:
#endif
        return CALG_AES_128;

    /* AES 192 */
    case POLARSSL_CIPHER_AES_192_ECB:
    case POLARSSL_CIPHER_AES_192_CBC:
    case POLARSSL_CIPHER_AES_192_CFB128:
    case POLARSSL_CIPHER_AES_192_CTR:
    case POLARSSL_CIPHER_AES_192_GCM:
#ifdef POLARSSL_CCM_C
    case POLARSSL_CIPHER_AES_192_CCM:
#endif
        return CALG_AES_192;

    /* AES 256 */
    case POLARSSL_CIPHER_AES_256_ECB:
    case POLARSSL_CIPHER_AES_256_CBC:
    case POLARSSL_CIPHER_AES_256_CFB128:
    case POLARSSL_CIPHER_AES_256_CTR:
    case POLARSSL_CIPHER_AES_256_GCM:
#ifdef POLARSSL_CCM_C
    case POLARSSL_CIPHER_AES_256_CCM:
#endif
        return CALG_AES_256;
#endif

    default:
        FIXME("unknown algorithm %d\n", ciphersuite_id);
        return 0;
    }
}

static ALG_ID schannel_get_mac_algid(int ciphersuite_id)
{
    const ssl_ciphersuite_t *cipher_suite = pssl_ciphersuite_from_id(ciphersuite_id);
    switch (cipher_suite->mac)
    {
    case POLARSSL_MD_NONE: return 0;
    case POLARSSL_MD_MD2: return CALG_MD2;
    case POLARSSL_MD_MD4: return CALG_MD4;
    case POLARSSL_MD_MD5: return CALG_MD5;
    case POLARSSL_MD_SHA1:
    case POLARSSL_MD_SHA224: return CALG_SHA;
    case POLARSSL_MD_SHA256: return CALG_SHA_256;
    case POLARSSL_MD_SHA384: return CALG_SHA_384;
    case POLARSSL_MD_SHA512: return CALG_SHA_512;
    //case POLARSSL_MD_RIPEMD160: return CALG_RIPEMD;
    default:
        FIXME("unknown algorithm %d\n", cipher_suite->mac);
        return 0;
    }
}

static ALG_ID schannel_get_kx_algid(int ciphersuite_id)
{
    const ssl_ciphersuite_t *cipher_suite = pssl_ciphersuite_from_id(ciphersuite_id);
    switch (cipher_suite->key_exchange)
    {
        case POLARSSL_KEY_EXCHANGE_NONE: return 0;
        case POLARSSL_KEY_EXCHANGE_RSA_PSK:
        case POLARSSL_KEY_EXCHANGE_ECDHE_RSA:
        case POLARSSL_KEY_EXCHANGE_RSA: return CALG_RSA_KEYX;
        case POLARSSL_KEY_EXCHANGE_DHE_PSK:
        case POLARSSL_KEY_EXCHANGE_DHE_RSA: return CALG_DH_EPHEM;
    default:
        FIXME("unknown algorithm %d\n", cipher_suite->key_exchange);
        return 0;
    }
}

unsigned int schan_imp_get_session_cipher_block_size(schan_imp_session session)
{
    POLARSSL_SESSION *s = (POLARSSL_SESSION *)session;
    TRACE("POLARSSL %p\n", session);

    return schannel_get_cipher_block_size(pssl_get_ciphersuite_id(pssl_get_ciphersuite(&s->ssl)));
}

unsigned int schan_imp_get_max_message_size(schan_imp_session session)
{
    POLARSSL_SESSION *s = (POLARSSL_SESSION *)session;
    TRACE("POLARSSL %p\n", session);

    return s->ssl.in_msglen;
}

SECURITY_STATUS schan_imp_get_connection_info(schan_imp_session session,
                                              SecPkgContext_ConnectionInfo *info)
{
    POLARSSL_SESSION *s = (POLARSSL_SESSION *)session;
    int ciphersuite_id;

    TRACE("POLARSSL %p %p\n", session, info);

    ciphersuite_id = pssl_get_ciphersuite_id(pssl_get_ciphersuite(&s->ssl));

    info->dwProtocol        = schannel_get_protocol(&s->ssl);
    info->aiCipher          = schannel_get_cipher_algid(ciphersuite_id);
    info->dwCipherStrength  = schannel_get_cipher_key_size(ciphersuite_id);
    info->aiHash            = schannel_get_mac_algid(ciphersuite_id);
    info->dwHashStrength    = schannel_get_mac_key_size(ciphersuite_id);
    info->aiExch            = schannel_get_kx_algid(ciphersuite_id);
    info->dwExchStrength    = schannel_get_kx_key_size(&s->ssl, ciphersuite_id); /* FIXME */
    return SEC_E_OK;
}

SECURITY_STATUS schan_imp_get_session_peer_certificate(schan_imp_session session, HCERTSTORE store,
                                                       PCCERT_CONTEXT *ret)
{
    POLARSSL_SESSION *s = (POLARSSL_SESSION *)session;
    PCCERT_CONTEXT cert_context = NULL;
    const x509_crt *next_cert;

    TRACE("POLARSSL %p %p %p %p\n", session, store, ret, ret != NULL ? *ret : NULL);

    if (!s->ssl.session->peer_cert)
        return SEC_E_INTERNAL_ERROR;

    for (next_cert = s->ssl.session->peer_cert; next_cert; next_cert = next_cert->next)
    {
        if (!CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING, next_cert->raw.p, next_cert->raw.len,
            CERT_STORE_ADD_REPLACE_EXISTING, (next_cert != s->ssl.session->peer_cert) ? NULL : &cert_context))
        {
            if (next_cert != s->ssl.session->peer_cert)
                CertFreeCertificateContext(cert_context);

            return GetLastError();
        }
    }

    *ret = cert_context;
    return SEC_E_OK;
}

SECURITY_STATUS schan_imp_send(schan_imp_session session, const void *buffer,
                               SIZE_T *length)
{
    POLARSSL_SESSION *s = (POLARSSL_SESSION *)session;
    ssize_t ret;

    TRACE("POLARSSL %p %p %lu\n", session, buffer, *length);

again:
    ret = pssl_write(&s->ssl, (unsigned char *)buffer, *length);

    if (ret >= 0)
    {
        *length = ret;
    }
    else if (ret == POLARSSL_ERR_NET_WANT_WRITE)
    {
        SIZE_T count = 0;

        if (schan_get_buffer(s->transport, &s->transport->out, &count))
            goto again;
        return SEC_I_CONTINUE_NEEDED;
    }
    else
    {
        ERR("ssl_write failed with -%x\n", -ret);
        return SEC_E_INTERNAL_ERROR;
    }

    return SEC_E_OK;
}

SECURITY_STATUS schan_imp_recv(schan_imp_session session, void *buffer,
                               SIZE_T *length)
{
    PPOLARSSL_SESSION s = (PPOLARSSL_SESSION)session;
    ssize_t ret;

    TRACE("POLARSSL %p %p %lu\n", session, buffer, *length);

again:
    ret = pssl_read(&s->ssl, (unsigned char *)buffer, *length);

    if (ret >= 0)
    {
        *length = ret;
    }
    else if (ret == POLARSSL_ERR_NET_WANT_READ)
    {
        SIZE_T count = 0;

        if (schan_get_buffer(s->transport, &s->transport->in, &count))
            goto again;
        return SEC_I_CONTINUE_NEEDED;
    }
    else
    {
        ERR("ssl_read failed with -%x\n", -ret);
        return SEC_E_INTERNAL_ERROR;
    }

    return SEC_E_OK;
}

BOOL schan_imp_allocate_certificate_credentials(schan_credentials *c)
{
    TRACE("POLARSSL %p %p %d\n", c, c->credentials, c->credential_use);

    c->credentials = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(x509_crt));
    if (!c->credentials)
        return FALSE;

    px509_crt_init((x509_crt *)c->credentials);
    return TRUE;
}

void schan_imp_free_certificate_credentials(schan_credentials *c)
{
    TRACE("POLARSSL %p %p %d\n", c, c->credentials, c->credential_use);

    if (!c->credentials)
        return;

    px509_crt_free((x509_crt *)c->credentials);
    HeapFree(GetProcessHeap(), 0, c->credentials);
}

BOOL schan_imp_init(void)
{
#ifdef __REACTOS__
    WCHAR pszSystemDir[MAX_PATH];

    TRACE("Schannel POLARSSL backend init\n");
    if (!GetSystemDirectoryW((LPWSTR)pszSystemDir, sizeof(pszSystemDir)/sizeof(WCHAR)))
    {
       ERR("GetSystemDirectory failed with error 0x%lx\n", GetLastError());
       return FALSE;
    }
    wcscat(pszSystemDir, L"\\mbedtls.dll");

    polarssl_handle = LoadLibraryExW(pszSystemDir, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!polarssl_handle)
    {
        ERR("Could not load %S\n", pszSystemDir);
        return FALSE;
    }

#define LOAD_FUNCPTR(f) \
    if (!(p##f = (void *)GetProcAddress(polarssl_handle, #f))) \
    { \
        ERR("Failed to load %s\n", #f); \
        goto fail; \
    }

#else
    TRACE("Schannel POLARSSL backend init\n");

    polarssl_handle = wine_dlopen("libpolarssl.so", RTLD_NOW, NULL, 0);
    if (!polarssl_handle)
    {
        ERR_(winediag)("Failed to load libpolarssl, secure connections will not be available.\n");
        return FALSE;
    }

#define LOAD_FUNCPTR(f) \
    if (!(p##f = wine_dlsym(polarssl_handle, #f, NULL, 0))) \
    { \
        ERR("Failed to load %s\n", #f); \
        goto fail; \
    }
#endif

    LOAD_FUNCPTR(ssl_init)
    LOAD_FUNCPTR(ssl_free)
    LOAD_FUNCPTR(ssl_set_endpoint)
    LOAD_FUNCPTR(ssl_set_authmode)
    LOAD_FUNCPTR(ssl_set_hostname)
    LOAD_FUNCPTR(ssl_set_renegotiation)
    LOAD_FUNCPTR(ssl_set_min_version)
    LOAD_FUNCPTR(ssl_set_max_version)
    LOAD_FUNCPTR(ssl_set_ca_chain)
    LOAD_FUNCPTR(ssl_set_rng)
    LOAD_FUNCPTR(ssl_set_bio)
    LOAD_FUNCPTR(ssl_set_verify)
    LOAD_FUNCPTR(ssl_get_peer_cert)
    LOAD_FUNCPTR(ssl_get_verify_result)
    LOAD_FUNCPTR(ssl_get_bytes_avail)
    LOAD_FUNCPTR(ssl_get_version)
    LOAD_FUNCPTR(ssl_get_ciphersuite)
    LOAD_FUNCPTR(ssl_get_ciphersuite_id)
    LOAD_FUNCPTR(ssl_ciphersuite_from_id)
    LOAD_FUNCPTR(ssl_handshake)
    LOAD_FUNCPTR(ssl_read)
    LOAD_FUNCPTR(ssl_write)
    LOAD_FUNCPTR(ssl_close_notify)
    LOAD_FUNCPTR(ssl_set_dbg)
    LOAD_FUNCPTR(debug_set_threshold)
    LOAD_FUNCPTR(entropy_init)
    LOAD_FUNCPTR(entropy_free)
    LOAD_FUNCPTR(entropy_func)
    LOAD_FUNCPTR(ctr_drbg_init)
    LOAD_FUNCPTR(ctr_drbg_free)
    LOAD_FUNCPTR(ctr_drbg_random)
    LOAD_FUNCPTR(x509_crt_init)
    LOAD_FUNCPTR(x509_crt_free)
    LOAD_FUNCPTR(x509_crt_parse)
    LOAD_FUNCPTR(x509_crt_info)
#undef LOAD_FUNCPTR

    if (TRACE_ON(secur32))
        pdebug_set_threshold(4);

    return TRUE;

fail:
    schan_imp_deinit();
    return FALSE;
}

void schan_imp_deinit(void)
{
    TRACE("Schannel POLARSSL backend deinit\n");
#ifdef __REACTOS__
    FreeLibrary(polarssl_handle);
#else
    wine_dlclose(polarssl_handle, NULL, 0);
#endif
    polarssl_handle = NULL;
}
