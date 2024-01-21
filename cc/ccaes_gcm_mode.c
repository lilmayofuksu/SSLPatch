#include "cc_gcm.h"
#include "ccaes_vng_gcm.h"

void ccmode_factory_gcm_decrypt(struct ccmode_gcm *gcm,
                                const struct ccmode_ecb *ecb_encrypt) {
    struct ccmode_gcm gcm_decrypt = CCMODE_FACTORY_GCM_DECRYPT(ecb_encrypt);
    *gcm = gcm_decrypt;
}

void ccmode_factory_gcm_encrypt(struct ccmode_gcm *gcm,
                                const struct ccmode_ecb *ecb_encrypt) {
    struct ccmode_gcm gcm_encrypt = CCMODE_FACTORY_GCM_ENCRYPT(ecb_encrypt);
    *gcm = gcm_encrypt;
}

extern const void *(*_ccaes_ecb_encrypt_mode)(void);
const struct ccmode_ecb *ccaes_ecb_encrypt_mode(void) {
    return (const struct ccmode_ecb*)_ccaes_ecb_encrypt_mode();
}

const struct ccmode_gcm *ccaes_gcm_decrypt_mode(void)
{
    static struct ccmode_gcm gcm_decrypt;
#if !defined(__SSLPATCH_NO_ASM__) && CCMODE_GCM_VNG_SPEEDUP
    ccaes_vng_gcm_decrypt_mode_setup(&gcm_decrypt);
#else
    const struct ccmode_ecb* ecb_base_encrypt_mode = ccaes_ecb_encrypt_mode();
    ccmode_factory_gcm_decrypt(&gcm_decrypt, ecb_base_encrypt_mode);
#endif
    return &gcm_decrypt;
}

const struct ccmode_gcm *ccaes_gcm_encrypt_mode(void)
{
    static struct ccmode_gcm gcm_encrypt;
#if !defined(__SSLPATCH_NO_ASM__) && CCMODE_GCM_VNG_SPEEDUP
    ccaes_vng_gcm_encrypt_mode_setup(&gcm_encrypt);
#else
    const struct ccmode_ecb* ecb_base_encrypt_mode = ccaes_ecb_encrypt_mode();
    ccmode_factory_gcm_encrypt(&gcm_encrypt, ecb_base_encrypt_mode);
#endif
    return &gcm_encrypt;
}
