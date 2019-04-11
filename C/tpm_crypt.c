/*
 * Copyright (C) 2019 Dream Property GmbH, Germany
 *                    https://dreambox.de/
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <assert.h>
#include <fcntl.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/x509_vfy.h>
#include <string.h>
#include <unistd.h>
#include "tpm_crypt.h"

static void tpm_rsa_pub1024(unsigned char dest[128],
                            const unsigned char src[128],
                            const unsigned char mod[128])
{
	BIGNUM *bbuf, *bexp, *bmod;
	BN_CTX *ctx;

	ctx = BN_CTX_new();
	bbuf = BN_new();
	bexp = BN_new();
	bmod = BN_new();

	BN_bin2bn(src, 128, bbuf);
	BN_bin2bn(mod, 128, bmod);
	BN_bin2bn((const unsigned char *)"\x01\x00\x01", 3, bexp);

	BN_mod_exp(bbuf, bbuf, bexp, bmod, ctx);

	BN_bn2bin(bbuf, dest);

	BN_clear_free(bexp);
	BN_clear_free(bmod);
	BN_clear_free(bbuf);
	BN_CTX_free(ctx);
}

bool tpm_decrypt(unsigned char dest[128],
                 const unsigned char *src, unsigned int len,
                 const unsigned char mod[128])
{
	unsigned char hash[20];
	SHA_CTX ctx;

	if ((len != 128) &&
	    (len != 202))
		return false;

	tpm_rsa_pub1024(dest, src, mod);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, &dest[1], 106);
	if (len == 202)
		SHA1_Update(&ctx, &src[131], 61);
	SHA1_Final(hash, &ctx);

	return memcmp(hash, &dest[107], 20) == 0;
}

bool tpm_validate_cert(unsigned char dest[128],
		      const unsigned char *src, unsigned int len,
		      const unsigned char mod[128])
{
	unsigned char buf[128];

	if (len != 210)
		return false;

	src += 8;
	len -= 8;

	if (!tpm_decrypt(buf, src, len, mod))
		return false;

	memcpy(&dest[0], &buf[36], 71);
	memcpy(&dest[71], &src[131], 57);

	return true;
}

static int tpm2_verify_cb(int ok, X509_STORE_CTX *ctx)
{
	if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_CERT_NOT_YET_VALID)
		return 1;

	return ok;
}

bool tpm2_validate_cert(const unsigned char *ca, unsigned int calen,
                        const unsigned char *ica, unsigned int icalen,
                        const unsigned char *leaf, unsigned int leaflen)
{
	const unsigned char *ptr;
	X509_STORE *store;
	X509 *cacert;
	STACK_OF(X509) *chain = NULL;
	bool ret = false;

	OpenSSL_add_all_algorithms();

	ptr = ca;
	cacert = d2i_X509(NULL, &ptr, calen);

	store = X509_STORE_new();
	X509_STORE_add_cert(store, cacert);

	if (ica && icalen) {
		chain = sk_X509_new_null();
		sk_X509_push(chain, d2i_X509(NULL, &ica, icalen));
	}

	if (leaf && leaflen) {
		X509 *cert = d2i_X509(NULL, &leaf, leaflen);
		X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();

		X509_STORE_CTX_init(store_ctx, store, cert, chain);
		X509_STORE_CTX_set_verify_cb(store_ctx, tpm2_verify_cb);
		if (X509_verify_cert(store_ctx) == 1)
			ret = true;
		X509_STORE_CTX_free(store_ctx);
		X509_free(cert);
	}

	sk_X509_pop_free(chain, X509_free);
	X509_STORE_free(store);
	X509_free(cacert);
	return ret;
}
