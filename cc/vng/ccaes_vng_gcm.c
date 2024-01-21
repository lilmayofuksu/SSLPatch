/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
 * 
 * corecrypto Internal Use License Agreement
 * 
 * IMPORTANT:  This Apple corecrypto software is supplied to you by Apple Inc. ("Apple")
 * in consideration of your agreement to the following terms, and your download or use
 * of this Apple software constitutes acceptance of these terms.  If you do not agree
 * with these terms, please do not download or use this Apple software.
 * 
 * 1.    As used in this Agreement, the term "Apple Software" collectively means and
 * includes all of the Apple corecrypto materials provided by Apple here, including
 * but not limited to the Apple corecrypto software, frameworks, libraries, documentation
 * and other Apple-created materials. In consideration of your agreement to abide by the
 * following terms, conditioned upon your compliance with these terms and subject to
 * these terms, Apple grants you, for a period of ninety (90) days from the date you
 * download the Apple Software, a limited, non-exclusive, non-sublicensable license
 * under Apple’s copyrights in the Apple Software to make a reasonable number of copies
 * of, compile, and run the Apple Software internally within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software; provided
 * that you must retain this notice and the following text and disclaimers in all
 * copies of the Apple Software that you make. You may not, directly or indirectly,
 * redistribute the Apple Software or any portions thereof. The Apple Software is only
 * licensed and intended for use as expressly stated above and may not be used for other
 * purposes or in other contexts without Apple's prior written permission.  Except as
 * expressly stated in this notice, no other rights or licenses, express or implied, are
 * granted by Apple herein.
 * 
 * 2.    The Apple Software is provided by Apple on an "AS IS" basis.  APPLE MAKES NO
 * WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED WARRANTIES
 * OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, REGARDING
 * THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN COMBINATION WITH YOUR PRODUCTS,
 * SYSTEMS, OR SERVICES. APPLE DOES NOT WARRANT THAT THE APPLE SOFTWARE WILL MEET YOUR
 * REQUIREMENTS, THAT THE OPERATION OF THE APPLE SOFTWARE WILL BE UNINTERRUPTED OR
 * ERROR-FREE, THAT DEFECTS IN THE APPLE SOFTWARE WILL BE CORRECTED, OR THAT THE APPLE
 * SOFTWARE WILL BE COMPATIBLE WITH FUTURE APPLE PRODUCTS, SOFTWARE OR SERVICES. NO ORAL
 * OR WRITTEN INFORMATION OR ADVICE GIVEN BY APPLE OR AN APPLE AUTHORIZED REPRESENTATIVE
 * WILL CREATE A WARRANTY. 
 * 
 * 3.    IN NO EVENT SHALL APPLE BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT, INCIDENTAL
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) ARISING
 * IN ANY WAY OUT OF THE USE, REPRODUCTION, COMPILATION OR OPERATION OF THE APPLE
 * SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF CONTRACT, TORT (INCLUDING
 * NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * 4.    This Agreement is effective until terminated. Your rights under this Agreement will
 * terminate automatically without notice from Apple if you fail to comply with any term(s)
 * of this Agreement.  Upon termination, you agree to cease all use of the Apple Software
 * and destroy all copies, full or partial, of the Apple Software. This Agreement will be
 * governed and construed in accordance with the laws of the State of California, without
 * regard to its choice of law rules.
 * 
 * You may report security issues about Apple products to product-security@apple.com,
 * as described here:  https://www.apple.com/support/security/.  Non-security bugs and
 * enhancement requests can be made via https://bugreport.apple.com as described
 * here: https://developer.apple.com/bug-reporting/
 *
 * EA1350 
 * 10/5/15
 */


#include "cc_config.h"
#include "cc_gcm.h"
#include "ccaes_vng_gcm.h"

#define CCMODE_GCM_VNG_SPEEDUP
#define CCAES_ARM

#if !defined(__SSLPATCH_NO_ASM__) && defined(CCMODE_GCM_VNG_SPEEDUP)

void ccaes_vng_gcm_init(const struct ccmode_gcm *gcm, ccgcm_ctx *key,
                     size_t rawkey_len, const void *rawkey) {
    const struct ccmode_ecb *ecb = gcm->custom;
    
    cc_assert(((VNG_GCM_TABLE_SIZE % CCN_UNIT_SIZE) == 0));
    cc_assert((((uintptr_t)key & 0xF) == 0)); // key context must be aligned on 16bytes

    _CCMODE_GCM_ECB_MODE(key)->ecb = ecb;
    _CCMODE_GCM_ECB_MODE(key)->ecb_key = &_CCMODE_GCM_KEY(key)->u[0] + VNG_GCM_TABLE_SIZE;

    ecb->init(ecb, CCMODE_GCM_KEY_ECB_KEY(key), rawkey_len, rawkey);

    /* gmac init: X=0, PAD=0, H = E(0) */
    cc_zero(16, CCMODE_GCM_KEY_X(key));
    cc_zero(16, CCMODE_GCM_KEY_PAD(key));
    ecb->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1, CCMODE_GCM_KEY_X(key), CCMODE_GCM_KEY_H(key));

    CCMODE_GCM_KEY_PAD_LEN(key) = 0;
    _CCMODE_GCM_KEY(key)->mode = CCMODE_GCM_MODE_IV;
    _CCMODE_GCM_KEY(key)->ivmode = 0;
    _CCMODE_GCM_KEY(key)->totlen = 0;
    _CCMODE_GCM_KEY(key)->pttotlen = 0;

    gcm_init(CCMODE_GCM_KEY_Htable(key), CCMODE_GCM_KEY_H(key));
}

/*!
 GCM GF multiplier (internal use only)  word oriented
 @param a   First value
 @param b   Second value
 @param c   Destination for a * b
 */
void ccaes_vng_gcm_gf_mult(const unsigned char *a, const unsigned char *b,
                           unsigned char *c) {
    gcm_gmult(b,a,c);
    return;
}

/*!
 GCM multiply by H
 @param gcm   The GCM state which holds the H value
 @param I     The value to multiply H by
 */
void ccaes_vng_gcm_mult_h(ccgcm_ctx *key, unsigned char *I) {
    ccaes_vng_gcm_gf_mult(CCMODE_GCM_KEY_Htable(key), I, I);
    return;
}

void ccaes_vng_gcm_set_iv(ccgcm_ctx *key, size_t iv_size, const void *iv) {
    size_t x, y;
    const uint8_t *IV = iv;

    /* must be in IV mode */
    cc_require(_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_IV, errOut); /* CRYPT_INVALID_ARG */

    /* trip the ivmode flag */
    if (iv_size + CCMODE_GCM_KEY_PAD_LEN(key) > 12) {
        _CCMODE_GCM_KEY(key)->ivmode |= 1;
    }

    x = 0;
#ifdef CCMODE_GCM_FAST
    if (CCMODE_GCM_KEY_PAD_LEN(key) == 0) {
        for (x = 0; x < (iv_size & ~15U); x += 16) {
            for (y = 0; y < 16; y += sizeof(CCMODE_GCM_FAST_TYPE)) {
                *((CCMODE_GCM_FAST_TYPE*)(&CCMODE_GCM_KEY_X(key)[y])) ^= *((const CCMODE_GCM_FAST_TYPE*)(&IV[x + y]));
            }
            ccaes_vng_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
            _CCMODE_GCM_KEY(key)->totlen += 128;
        }
        IV += x;
    }
#endif

    /* start adding IV data to the state */
    for (; x < iv_size; x++) {
        CCMODE_GCM_KEY_PAD(key)[CCMODE_GCM_KEY_PAD_LEN(key)++] = *IV++;

        if (CCMODE_GCM_KEY_PAD_LEN(key) == 16) {
            /* GF mult it */
            for (y = 0; y < 16; y++) {
                CCMODE_GCM_KEY_X(key)[y] ^= CCMODE_GCM_KEY_PAD(key)[y];
            }
            ccaes_vng_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
            CCMODE_GCM_KEY_PAD_LEN(key) = 0;
            _CCMODE_GCM_KEY(key)->totlen += 128;
        }
    }
errOut:
    return;/* CRYPT_INVALID_ARG */
}

void ccaes_vng_gcm_gmac(ccgcm_ctx *key, size_t nbytes, const void *in) {
    const char *bytes = in;
    size_t x;
#ifdef CCMODE_GCM_FAST
    size_t y;
#endif

    /* in IV mode? */
    if (_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_IV) {
        /* let's process the IV */
        if (_CCMODE_GCM_KEY(key)->ivmode || CCMODE_GCM_KEY_PAD_LEN(key) != 12) {
            for (x = 0; x < CCMODE_GCM_KEY_PAD_LEN(key); x++) {
                CCMODE_GCM_KEY_X(key)[x] ^= CCMODE_GCM_KEY_PAD(key)[x];
            }
            if (CCMODE_GCM_KEY_PAD_LEN(key)) {
                _CCMODE_GCM_KEY(key)->totlen += CCMODE_GCM_KEY_PAD_LEN(key) * (uint64_t)(8);
                ccaes_vng_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
            }

            /* mix in the length */
            cc_zero(8, CCMODE_GCM_KEY_PAD(key));
            CC_STORE64_BE(_CCMODE_GCM_KEY(key)->totlen, CCMODE_GCM_KEY_PAD(key)+8);
            for (x = 0; x < 16; x++) {
                CCMODE_GCM_KEY_X(key)[x] ^= CCMODE_GCM_KEY_PAD(key)[x];
            }
            ccaes_vng_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));

            /* copy counter out */
            CC_MEMCPY(CCMODE_GCM_KEY_Y(key), CCMODE_GCM_KEY_X(key), 16);
            cc_zero(16, CCMODE_GCM_KEY_X(key));
        } else {
            CC_MEMCPY(CCMODE_GCM_KEY_Y(key), CCMODE_GCM_KEY_PAD(key), 12);
            CCMODE_GCM_KEY_Y(key)[12] = 0;
            CCMODE_GCM_KEY_Y(key)[13] = 0;
            CCMODE_GCM_KEY_Y(key)[14] = 0;
            CCMODE_GCM_KEY_Y(key)[15] = 1;
        }
        CC_MEMCPY(CCMODE_GCM_KEY_Y_0(key), CCMODE_GCM_KEY_Y(key), 16);
        //cc_zero(16, CCMODE_GCM_KEY_PAD(key));
        CCMODE_GCM_KEY_PAD_LEN(key) = 0;
        _CCMODE_GCM_KEY(key)->totlen = 0;
        _CCMODE_GCM_KEY(key)->mode   = CCMODE_GCM_MODE_AAD;
    }

    cc_require(_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_AAD && CCMODE_GCM_KEY_PAD_LEN(key) < 16,errOut); /* CRYPT_INVALID_ARG */

    x = 0;
#ifdef CCMODE_GCM_FAST
    if (CCMODE_GCM_KEY_PAD_LEN(key) == 0) {
#ifdef  __x86_64__
    if (CC_HAS_AESNI() && CC_HAS_SupplementalSSE3())
#endif
        if (nbytes >= 16) {
            size_t j = (size_t) (nbytes & (-16));
            gcm_ghash(CCMODE_GCM_KEY_X(key), (void *) CCMODE_GCM_KEY_Htable(key), (const void*) bytes, j);
            bytes += j;    
			nbytes -= j;
            _CCMODE_GCM_KEY(key)->totlen += (j<<3);
        }
        for (x = 0; x < (nbytes & ~15UL); x += 16) {
            for (y = 0; y < 16; y += sizeof(CCMODE_GCM_FAST_TYPE)) {
                *((CCMODE_GCM_FAST_TYPE*)(&CCMODE_GCM_KEY_X(key)[y])) ^= *((const CCMODE_GCM_FAST_TYPE*)(&bytes[x + y]));
            }
            ccaes_vng_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
            _CCMODE_GCM_KEY(key)->totlen += 128;
        }
        bytes += x;
    }
#endif

    /* start adding AAD data to the state */
    for (; x < nbytes; x++) {
        CCMODE_GCM_KEY_X(key)[CCMODE_GCM_KEY_PAD_LEN(key)++] ^= *bytes++;

        if (CCMODE_GCM_KEY_PAD_LEN(key) == 16) {
            /* GF mult it */
            ccaes_vng_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
            CCMODE_GCM_KEY_PAD_LEN(key) = 0;
            _CCMODE_GCM_KEY(key)->totlen += 128;
        }
    }
errOut:
    return;
}

void ccaes_vng_gcm_finalize(ccgcm_ctx *key, size_t tag_size, void *tag) {
    size_t x;

    cc_require(_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_TEXT,errOut); /* CRYPT_INVALID_ARG */

    /* handle remaining ciphertext */
    if (CCMODE_GCM_KEY_PAD_LEN(key)) {
        _CCMODE_GCM_KEY(key)->pttotlen += CCMODE_GCM_KEY_PAD_LEN(key) * (uint64_t)(8);
        ccaes_vng_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
    }

    /* length */
    CC_STORE64_BE(_CCMODE_GCM_KEY(key)->totlen, CCMODE_GCM_KEY_PAD(key));
    CC_STORE64_BE(_CCMODE_GCM_KEY(key)->pttotlen, CCMODE_GCM_KEY_PAD(key)+8);
    for (x = 0; x < 16; x++) {
        CCMODE_GCM_KEY_X(key)[x] ^= CCMODE_GCM_KEY_PAD(key)[x];
    }
    ccaes_vng_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));

    /* encrypt original counter */
    CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                 CCMODE_GCM_KEY_Y_0(key),
                                 CCMODE_GCM_KEY_PAD(key));
    uint8_t *out = tag;
    for (x = 0; x < 16 && x < tag_size; x++) {
        out[x] = CCMODE_GCM_KEY_PAD(key)[x] ^ CCMODE_GCM_KEY_X(key)[x];
    }
errOut:
    return;
}

void ccaes_vng_gcm_encrypt(ccgcm_ctx *key, size_t nbytes,
                       const void *in, void *out) {
    size_t x, y;
    unsigned char b;
    
    if (_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_IV) {
        // This allows the gmac routine to be skipped by callers.
        ccaes_vng_gcm_gmac(key, 0, NULL);
    }
    /* in AAD mode? */
    if (_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_AAD) {
        /* let's process the AAD */
        if (CCMODE_GCM_KEY_PAD_LEN(key)) {
            _CCMODE_GCM_KEY(key)->totlen += CCMODE_GCM_KEY_PAD_LEN(key) * (uint64_t)(8);
            ccaes_vng_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
        }

        /* increment counter */
        for (y = 15; y >= 12; y--) {
            if (++CCMODE_GCM_KEY_Y(key)[y] & 255) { break; }
        }
        /* encrypt the counter */
        CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                     CCMODE_GCM_KEY_Y(key),
                                     CCMODE_GCM_KEY_PAD(key));
        CCMODE_GCM_KEY_PAD_LEN(key) = 0;
        _CCMODE_GCM_KEY(key)->mode   = CCMODE_GCM_MODE_TEXT;
        _CCMODE_GCM_KEY(key)->pttotlen = 0;
    }

    cc_require(_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_TEXT,errOut); /* CRYPT_INVALID_ARG */

    x = 0;
    const unsigned char *pt = in;
    unsigned char *ct = out;
#ifdef CCMODE_GCM_FAST
    if (CCMODE_GCM_KEY_PAD_LEN(key) == 0) {

#ifdef  __x86_64__
        if (CC_HAS_AESNI() && CC_HAS_SupplementalSSE3()) 
#endif

        if (nbytes >= 16) {
            unsigned int j = (unsigned int) (nbytes & (-16));
#ifdef  __x86_64__
            if (CC_HAS_AVX1())
                gcmEncrypt_avx1(pt, ct, _CCMODE_GCM_KEY(key), j, CCMODE_GCM_KEY_Htable(key), CCMODE_GCM_KEY_ECB_KEY(key));
            else
                gcmEncrypt_SupplementalSSE3(pt, ct, _CCMODE_GCM_KEY(key), j, CCMODE_GCM_KEY_Htable(key), CCMODE_GCM_KEY_ECB_KEY(key));
#else
            gcmEncrypt(pt, ct, _CCMODE_GCM_KEY(key), j, CCMODE_GCM_KEY_Htable(key), CCMODE_GCM_KEY_ECB_KEY(key));
#endif
            ct += j;    pt += j;    nbytes -= j;
			_CCMODE_GCM_KEY(key)->pttotlen += (j<<3);
#if !defined(__ARM_NEON__) || defined(__arm64__)            
            CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                         CCMODE_GCM_KEY_Y(key),
                                         CCMODE_GCM_KEY_PAD(key));
#endif

        }

        for (x = 0; x < (nbytes & ~15U); x += 16) {
            /* ctr encrypt */
            for (y = 0; y < 16; y += sizeof(CCMODE_GCM_FAST_TYPE)) {
                *((CCMODE_GCM_FAST_TYPE*)(&ct[x + y])) = *((const CCMODE_GCM_FAST_TYPE*)(&pt[x+y])) ^ *((CCMODE_GCM_FAST_TYPE*)(&CCMODE_GCM_KEY_PAD(key)[y]));
                *((CCMODE_GCM_FAST_TYPE*)(&_CCMODE_GCM_KEY(key)->X[y])) ^= *((CCMODE_GCM_FAST_TYPE*)(&ct[x+y]));
            }
            /* GMAC it */
            _CCMODE_GCM_KEY(key)->pttotlen += 128;
            ccaes_vng_gcm_mult_h(key, _CCMODE_GCM_KEY(key)->X);
            /* increment counter */
            for (y = 15; y >= 12; y--) {
                if (++CCMODE_GCM_KEY_Y(key)[y] & 255) { break; }
            }
            CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                         CCMODE_GCM_KEY_Y(key),
                                         CCMODE_GCM_KEY_PAD(key));
        }
    }
#endif // CCMODE_GCM_FAST

    /* process text */
    for (; x < nbytes; x++) {
        if (CCMODE_GCM_KEY_PAD_LEN(key) == 16) {
            _CCMODE_GCM_KEY(key)->pttotlen += 128;
            ccaes_vng_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));

            /* increment counter */
            for (y = 15; y >= 12; y--) {
                if (++CCMODE_GCM_KEY_Y(key)[y] & 255) { break; }
            }
            CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                         CCMODE_GCM_KEY_Y(key),
                                         CCMODE_GCM_KEY_PAD(key));
            CCMODE_GCM_KEY_PAD_LEN(key) = 0;
        }

        b = ct[x] = pt[x] ^ CCMODE_GCM_KEY_PAD(key)[CCMODE_GCM_KEY_PAD_LEN(key)];
        CCMODE_GCM_KEY_X(key)[CCMODE_GCM_KEY_PAD_LEN(key)++] ^= b;
    }
errOut:
    return;
}

void ccaes_vng_gcm_decrypt(ccgcm_ctx *key, size_t nbytes,
                        const void *in, void *out) {
    size_t x, y;
    unsigned char b;

    if (_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_IV) {
        // This allows the gmac routine to be skipped by callers.
        ccaes_vng_gcm_gmac(key, 0, NULL);
    }
    /* in AAD mode? */
    if (_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_AAD) {
        /* let's process the AAD */
        if (CCMODE_GCM_KEY_PAD_LEN(key)) {
            _CCMODE_GCM_KEY(key)->totlen += CCMODE_GCM_KEY_PAD_LEN(key) * (uint64_t)(8);
            ccaes_vng_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));
        }

        /* increment counter */
        for (y = 15; y >= 12; y--) {
            if (++CCMODE_GCM_KEY_Y(key)[y] & 255) { break; }
        }
        /* encrypt the counter */
        CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                     CCMODE_GCM_KEY_Y(key),
                                     CCMODE_GCM_KEY_PAD(key));
        CCMODE_GCM_KEY_PAD_LEN(key) = 0;
        _CCMODE_GCM_KEY(key)->mode   = CCMODE_GCM_MODE_TEXT;
        _CCMODE_GCM_KEY(key)->pttotlen = 0;
    }

    cc_require(_CCMODE_GCM_KEY(key)->mode == CCMODE_GCM_MODE_TEXT,errOut); /* CRYPT_INVALID_ARG */

    x = 0;
    const unsigned char *ct = in;
    unsigned char *pt = out;
#ifdef CCMODE_GCM_FAST
    if (CCMODE_GCM_KEY_PAD_LEN(key) == 0) {

#ifdef  __x86_64__
        if (CC_HAS_AESNI() && CC_HAS_SupplementalSSE3()) 
#endif
		if (nbytes >= 16) {
			unsigned int j = (unsigned int) (nbytes & (-16)); 
#ifdef  __x86_64__
            if (CC_HAS_AVX1())
			    gcmDecrypt_avx1(ct, pt, _CCMODE_GCM_KEY(key), j, CCMODE_GCM_KEY_Htable(key), CCMODE_GCM_KEY_ECB_KEY(key));
            else
			    gcmDecrypt_SupplementalSSE3(ct, pt, _CCMODE_GCM_KEY(key), j, CCMODE_GCM_KEY_Htable(key), CCMODE_GCM_KEY_ECB_KEY(key));
#else
			gcmDecrypt(ct, pt, _CCMODE_GCM_KEY(key), j, CCMODE_GCM_KEY_Htable(key), CCMODE_GCM_KEY_ECB_KEY(key));
#endif
			ct += j;	pt += j;	nbytes -= j;
            _CCMODE_GCM_KEY(key)->pttotlen += (j<<3);
#if !defined(__ARM_NEON__) || defined(__arm64__)
            CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                         CCMODE_GCM_KEY_Y(key),
                                         CCMODE_GCM_KEY_PAD(key));
#endif
		}

        for (x = 0; x < (nbytes & ~15U); x += 16) {
            /* ctr encrypt */
            for (y = 0; y < 16; y += sizeof(CCMODE_GCM_FAST_TYPE)) {
                *((CCMODE_GCM_FAST_TYPE*)(&_CCMODE_GCM_KEY(key)->X[y])) ^= *((const CCMODE_GCM_FAST_TYPE*)(&ct[x+y]));
                *((CCMODE_GCM_FAST_TYPE*)(&pt[x + y])) = *((const CCMODE_GCM_FAST_TYPE*)(&ct[x+y])) ^ *((CCMODE_GCM_FAST_TYPE*)(&CCMODE_GCM_KEY_PAD(key)[y]));
            }
            /* GMAC it */
            _CCMODE_GCM_KEY(key)->pttotlen += 128;
            ccaes_vng_gcm_mult_h(key, _CCMODE_GCM_KEY(key)->X);
            /* increment counter */
            for (y = 15; y >= 12; y--) {
                if (++CCMODE_GCM_KEY_Y(key)[y] & 255) { break; }
            }
            CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                         CCMODE_GCM_KEY_Y(key),
                                         CCMODE_GCM_KEY_PAD(key));
        }
    }
#endif // CCMODE_GCM_FAST

    /* process text */
    for (; x < nbytes; x++) {
        if (CCMODE_GCM_KEY_PAD_LEN(key) == 16) {
            _CCMODE_GCM_KEY(key)->pttotlen += 128;
            ccaes_vng_gcm_mult_h(key, CCMODE_GCM_KEY_X(key));

            /* increment counter */
            for (y = 15; y >= 12; y--) {
                if (++CCMODE_GCM_KEY_Y(key)[y] & 255) { break; }
            }
            CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                         CCMODE_GCM_KEY_Y(key),
                                         CCMODE_GCM_KEY_PAD(key));
            CCMODE_GCM_KEY_PAD_LEN(key) = 0;
        }

        b = ct[x];
        pt[x] = ct[x] ^ CCMODE_GCM_KEY_PAD(key)[CCMODE_GCM_KEY_PAD_LEN(key)];
        CCMODE_GCM_KEY_X(key)[CCMODE_GCM_KEY_PAD_LEN(key)++] ^= b;
    }
errOut:
    return;
}

#endif