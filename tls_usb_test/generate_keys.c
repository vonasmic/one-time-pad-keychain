/* gen_hybrid_cert.c
 * Generates a Hybrid (ECC P-384 + Dilithium 3) Certificate + Keys.
 * FIX: Now exports Dilithium Key in valid PKCS#8 format.
 */

 #include <wolfssl/options.h>
 #include <wolfssl/wolfcrypt/settings.h>
 #include <wolfssl/ssl.h>
 #include <wolfssl/wolfcrypt/asn.h>
 #include <wolfssl/wolfcrypt/asn_public.h>
 #include <wolfssl/wolfcrypt/ecc.h>
 #include <wolfssl/wolfcrypt/dilithium.h>
 #include <wolfssl/wolfcrypt/error-crypt.h>
 #include <wolfssl/wolfcrypt/random.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 
 #define KEY_FILE      "certs/ecc-server-key.pem"
 #define DIL_KEY_FILE  "certs/dilithium-server.priv"
 #define CERT_FILE     "certs/server-cert-hybrid.pem"
 
 void err_sys(const char* msg, int err) {
     char buffer[80];
     fprintf(stderr, "Error: %s (Code: %d)\n", msg, err);
     fprintf(stderr, "wolfSSL Info: %s\n", wolfSSL_ERR_error_string(err, buffer));
     exit(EXIT_FAILURE);
 }
 
 /* Helper to write generic PEM file */
 int WritePEM(const char* fname, const char* header, const byte* der, int derSz) {
     FILE* f = fopen(fname, "wb");
     if (!f) return -1;
     
     int pemSz = derSz * 2 + 2048;
     byte* pemBuf = (byte*)malloc(pemSz);
     
     /* Always use ECC_PRIVATEKEY_TYPE to get basic PEM formatting, 
      * but we strip the "EC " part manually if needed to be generic. */
     int ret = wc_DerToPem(der, derSz, pemBuf, pemSz, ECC_PRIVATEKEY_TYPE);
     
     if (ret > 0) {
         /* Replace header if user requested specific header */
         if (strstr(header, "PRIVATE KEY") && !strstr(header, "EC ")) {
             /* Hack: Convert "-----BEGIN EC PRIVATE KEY-----" to "-----BEGIN PRIVATE KEY-----" */
             /* by overwriting "EC " with spaces or shifting. Simple shift: */
             char* str = (char*)pemBuf;
             char* start = strstr(str, "EC PRIVATE KEY");
             while (start) {
                 memmove(start, start + 3, strlen(start + 3) + 1);
                 ret -= 3;
                 start = strstr(str, "EC PRIVATE KEY");
             }
         }
         /* If user requested CERTIFICATE, header is already correct from CERT_TYPE (logic handled in main if needed) */
         /* Ideally wc_DerToPem handles types, but for custom headers we do this: */
         if (strstr(header, "CERTIFICATE")) {
              /* Re-encode with CERT_TYPE to get correct header */
              ret = wc_DerToPem(der, derSz, pemBuf, pemSz, CERT_TYPE);
         }
         
         fwrite(pemBuf, 1, ret, f);
         ret = 0;
     }
     
     free(pemBuf);
     fclose(f);
     return ret;
 }
 
 /* [NEW] Helper to wrap Raw Key in PKCS#8 and Write PEM */
 int WriteDilithiumPKCS8(const char* fname, const byte* rawKey, int rawKeySz) {
     int ret;
     byte* pkcs8Buf = (byte*)malloc(rawKeySz + 512); /* Header overhead */
     word32 pkcs8Sz = rawKeySz + 512;
 
     /* wrap the raw key into a PKCS#8 Info structure.
      * OID for Dilithium 3 is handled by the ALGO ID mapping in wolfCrypt.
      * Ensure we pass the correct Algo ID: CTC_ML_DSA_LEVEL3
      */
     ret = wc_CreatePKCS8Key(pkcs8Buf, &pkcs8Sz, rawKey, rawKeySz, CTC_ML_DSA_LEVEL3, NULL, 0);
     
     if (ret == 0) {
         /* Now write this PKCS#8 DER to PEM with standard "PRIVATE KEY" header */
         ret = WritePEM(fname, "PRIVATE KEY", pkcs8Buf, pkcs8Sz);
     }
     
     free(pkcs8Buf);
     return ret;
 }
 
 int main(void) {
     int ret;
     WC_RNG rng;
     Cert myCert;
     DecodedCert preTBS;
     
     /* Keys */
     ecc_key eccKey;
     dilithium_key dilKey;
     
     /* Buffers */
     byte* certBuf = (byte*)malloc(8192); 
     byte* keyBuf  = (byte*)malloc(4096);
     byte* dilPubKeyDer = (byte*)malloc(4096); 
     byte* altSigAlgBuf = (byte*)malloc(256); 
     byte* preTbsBuf = (byte*)malloc(8192); 
     byte* altSigValBuf = (byte*)malloc(4096); 
     
     word32 dilPubKeySz = 4096;
     word32 altSigAlgSz = 256;
     word32 preTbsSz = 8192;
     word32 altSigValSz = 4096;
     
     printf("Initializing...\n");
     wolfSSL_Init();
     wc_InitRng(&rng);
     wc_ecc_init(&eccKey);
     wc_dilithium_init(&dilKey);
     wc_InitCert(&myCert);
 
     /* 1. GENERATE ECC P-384 KEY (NATIVE) */
     printf("Generating ECC P-384 Key...\n");
     ret = wc_ecc_make_key_ex(&rng, 48, &eccKey, ECC_SECP384R1);
     if (ret != 0) err_sys("ECC Key Gen failed", ret);
 
     ret = wc_EccKeyToDer(&eccKey, keyBuf, 4096);
     if (ret < 0) err_sys("ECC Key Export failed", ret);
     WritePEM(KEY_FILE, "EC PRIVATE KEY", keyBuf, ret);
     printf("Saved %s\n", KEY_FILE);
 
     /* 2. GENERATE DILITHIUM 3 KEY (ALTERNATIVE) */
     printf("Generating Dilithium 3 Key...\n");
     ret = wc_dilithium_set_level(&dilKey, WC_ML_DSA_65);
     if (ret != 0) err_sys("Dilithium Set Level failed", ret);
     
     ret = wc_dilithium_make_key(&dilKey, &rng); 
     if (ret != 0) err_sys("Dilithium Key Gen failed", ret);
 
     /* Export Raw Key first */
     word32 dilKeySz = 4096;
     ret = wc_dilithium_export_private(&dilKey, keyBuf, &dilKeySz);
     if (ret != 0) err_sys("Dilithium Key Export failed", ret);
     
     /* [FIX] Save as PKCS#8 PEM so wolfSSL can load it properly */
     if (WriteDilithiumPKCS8(DIL_KEY_FILE, keyBuf, dilKeySz) != 0) {
         err_sys("Write PKCS8 failed", -1);
     }
     printf("Saved %s (PKCS#8 format)\n", DIL_KEY_FILE);
 
     /* 3. EXPORT DILITHIUM PUBLIC KEY */
     printf("Exporting Dilithium Public Key...\n");
     ret = wc_Dilithium_PublicKeyToDer(&dilKey, dilPubKeyDer, dilPubKeySz, 1);
     if (ret < 0) err_sys("Dilithium Public Key Export failed", ret);
     dilPubKeySz = ret;
     
     /* Save Public Key (Required for CLI tools/verification) */
     WritePEM("certs/dilithium-server.pub", "PUBLIC KEY", dilPubKeyDer, dilPubKeySz);
     printf("Saved certs/dilithium-server.pub\n");
 
     /* 4. CONFIGURE CERTIFICATE */
     printf("Constructing Hybrid Certificate...\n");
     strncpy(myCert.subject.country, "US", CTC_NAME_SIZE);
     strncpy(myCert.subject.state,   "Washington", CTC_NAME_SIZE);
     strncpy(myCert.subject.org,     "Hybrid Corp", CTC_NAME_SIZE);
     strncpy(myCert.subject.commonName, "localhost", CTC_NAME_SIZE);
     
     myCert.isCA    = 0;
     myCert.daysValid = 365;
     myCert.selfSigned = 1; 
     myCert.sigType = CTC_SHA384wECDSA; 
 
     /* 5. SET DUAL ALGORITHM EXTENSIONS */
     #ifdef WOLFSSL_DUAL_ALG_CERTS
         printf("Setting Dual Algorithm Extensions...\n");
         
         ret = wc_SetCustomExtension(&myCert, 0, "2.5.29.72", dilPubKeyDer, dilPubKeySz);
         if (ret != 0) err_sys("SetCustomExtension (SAPKI) failed", ret);
         
         /* Correct Algo ID for Dilithium 3 */
         altSigAlgSz = SetAlgoID(CTC_ML_DSA_LEVEL3, altSigAlgBuf, oidSigType, 0);
         if (altSigAlgSz <= 0) err_sys("SetAlgoID failed", altSigAlgSz);
         
         ret = wc_SetCustomExtension(&myCert, 0, "2.5.29.73", altSigAlgBuf, altSigAlgSz);
         if (ret != 0) err_sys("SetCustomExtension (AltSigAlg) failed", ret);
         
         printf("Dual Alg Extensions set.\n");
     #endif
 
     /* 6. INITIAL CERT */
     printf("Generating initial certificate...\n");
     ret = wc_MakeCert_ex(&myCert, certBuf, 8192, ECC_TYPE, &eccKey, &rng);
     if (ret < 0) err_sys("MakeCert_ex failed", ret);
     ret = wc_SignCert_ex(myCert.bodySz, myCert.sigType, certBuf, 8192, ECC_TYPE, &eccKey, &rng);
     if (ret < 0) err_sys("SignCert_ex failed", ret);
 
     /* 7. PRE-TBS AND SIGN WITH DILITHIUM */
     printf("Signing with Dilithium...\n");
     wc_InitDecodedCert(&preTBS, certBuf, ret, NULL);
     wc_ParseCert(&preTBS, CERT_TYPE, NO_VERIFY, NULL);
     preTbsSz = wc_GeneratePreTBS(&preTBS, preTbsBuf, preTbsSz);
     
     altSigValSz = wc_MakeSigWithBitStr(altSigValBuf, altSigValSz, 
                                        CTC_ML_DSA_LEVEL3, preTbsBuf, preTbsSz,
                                        ML_DSA_LEVEL3_TYPE, &dilKey, &rng);
     if (altSigValSz <= 0) err_sys("MakeSigWithBitStr failed", altSigValSz);
     wc_FreeDecodedCert(&preTBS);
 
     /* 8. SET ALT SIGNATURE */
     ret = wc_SetCustomExtension(&myCert, 0, "2.5.29.74", altSigValBuf, altSigValSz);
     if (ret != 0) err_sys("SetCustomExtension (AltSigVal) failed", ret);
 
     /* 9. FINAL CERT */
     printf("Generating final hybrid certificate...\n");
     ret = wc_MakeCert_ex(&myCert, certBuf, 8192, ECC_TYPE, &eccKey, &rng);
     if (ret < 0) err_sys("MakeCert_ex (final) failed", ret);
     ret = wc_SignCert_ex(myCert.bodySz, myCert.sigType, certBuf, 8192, ECC_TYPE, &eccKey, &rng);
     if (ret < 0) err_sys("SignCert_ex (final) failed", ret);
 
     /* 10. SAVE CERT */
     WritePEM(CERT_FILE, "CERTIFICATE", certBuf, ret);
     printf("Saved %s (Size: %d bytes)\n", CERT_FILE, ret);
 
     /* Cleanup */
     wc_ecc_free(&eccKey);
     wc_dilithium_free(&dilKey);
     free(certBuf); free(keyBuf); free(dilPubKeyDer);
     free(altSigAlgBuf); free(preTbsBuf); free(altSigValBuf);
     wolfSSL_Cleanup();
     
     printf("Done.\n");
     return 0;
 }