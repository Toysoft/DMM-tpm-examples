#!/usr/bin/env python
#
# Copyright (C) 2019 Dream Property GmbH, Germany
#                    https://dreambox.de/
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
from enigma import eTPM


tpm_ca_key='''
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAJ985EfJtPQjJs6z/trJVWDYjHNvkJtcYsCJ0YyeSlTFWKG4EzVFAsmy
5nSJ3s2dEd3H9OTkvNuc6n2t2nRym9y8GDPnr3yuDOO1hI0NjZ0y0M7VcQmEY6gp
mdw8Injoh48CO1Nt1fCjX7dUCd6n8cmuitfSz7IuE/usat+xHTo/AgMBAAE=
-----END RSA PUBLIC KEY-----
'''

tpm2_ca_cert='''
-----BEGIN CERTIFICATE-----
MIIB4zCCAYigAwIBAgIJAPlpd2WyK3K4MAoGCCqGSM49BAMCMEQxCzAJBgNVBAYT
AkRFMRwwGgYDVQQKDBNEcmVhbSBQcm9wZXJ0eSBHbWJIMRcwFQYDVQQDDA5EUjEw
MDAgUm9vdCBDQTAeFw0xODExMTUyMjI3NDNaFw0zODExMTAyMjI3NDNaMEQxCzAJ
BgNVBAYTAkRFMRwwGgYDVQQKDBNEcmVhbSBQcm9wZXJ0eSBHbWJIMRcwFQYDVQQD
DA5EUjEwMDAgUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBHdlqId
cxOtxJfbl3hhQ1kCuesm9eLXUGJ2S7i9X1uYyQLL8uUCT8h3jZeahsMQGybe+W4U
7z8OAFR0eZcvd52jYzBhMB0GA1UdDgQWBBSr0Bezu08YXxR7+/8PYJ91CcoSFTAf
BgNVHSMEGDAWgBSr0Bezu08YXxR7+/8PYJ91CcoSFTAPBgNVHRMBAf8EBTADAQH/
MA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDAgNJADBGAiEA75Ekbw5XOLe6d9e0
5i/Sf+V+65fsM6JQbZV+xjRQQPkCIQC6P8fAbhryha7YhzJkm3NCjArnzNzTNRB+
BB//MMozyQ==
-----END CERTIFICATE-----
'''


class Util():
    @staticmethod
    def bytes_from_long(num, size):
        return bytes(bytearray([(num >> ((size - byte - 1) * 8)) & 0xff for byte in range(size)]))


    @staticmethod
    def long_from_bytes(b):
        return reduce(lambda x, y: (x << 8) + y, b)


    @staticmethod
    def random_bytes(count):
        from os import getpid, urandom
        from time import clock, time

        while True:
            rng1 = urandom(count)
            rng2 = urandom(count)
            if rng1 != rng2:
                break

        buf = [ord(a) ^ ord(b) for a, b in zip(rng1, rng2)]

        num = Util.long_from_bytes(buf)
        num ^= long(clock() * 1000)
        num ^= long(time() * 1000)
        num ^= getpid()

        return Util.bytes_from_long(num, count)


    @staticmethod
    def rsa(src, exp, mod):
        return Util.bytes_from_long(pow(Util.long_from_bytes(src), exp, mod), len(src))


class TPMv1():
    @staticmethod
    def decrypt_block(src, pubkey):
        from cryptography.hazmat.primitives.hashes import Hash, SHA1

        if len(src) != 128 and len(src) != 202:
            return None

        dest = Util.rsa(src[:128], pubkey.e, pubkey.n)

        digest = Hash(SHA1(), backend=default_backend())
        digest.update(dest[1:107])
        if len(src) == 202:
            digest.update(bytes(src[131:192]))
        if digest.finalize() == dest[107:127]:
            return dest

        return None


    @staticmethod
    def validate_cert(cert, pubkey):
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

        buf = TPMv1.decrypt_block(cert[8:], pubkey)
        if buf is None:
            return None
        mod = bytearray(buf[36:107] + cert[139:196])
        return RSAPublicNumbers(pubkey.e, Util.long_from_bytes(mod))


class TPMv2():
    @staticmethod
    def validate_cert(chain, leaf):
        from datetime import timedelta
        from OpenSSL.crypto import X509, X509Store, X509StoreContext, X509StoreContextError

        store = X509Store()
        store.set_time(leaf.not_valid_before + timedelta(days=1))
        for c in chain:
            store.add_cert(X509.from_cryptography(c))

        x509_leaf = X509.from_cryptography(leaf)
        ctx = X509StoreContext(store, x509_leaf)
        try:
            ctx.verify_certificate()
        except X509StoreContextError as e:
            return False

        return True


    @staticmethod
    def verify_signature(sig, data, pubkey):
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from pyasn1.codec.ber.encoder import encode
        from pyasn1.type.univ import Integer, SequenceOf

        if len(sig) != 64:
            return False

        seq = SequenceOf(componentType=Integer())
        seq[0] = Util.long_from_bytes(sig[:32])
        seq[1] = Util.long_from_bytes(sig[32:])

        try:
            pubkey.verify(encode(seq), data, ECDSA(SHA256()))
        except:
            return False

        return True


etpm = eTPM()
version = etpm.getData(eTPM.DT_TPM_VERSION)
ica_cert = etpm.getData(eTPM.DT_LEVEL2_CERT)
leaf_cert = etpm.getData(eTPM.DT_LEVEL3_CERT)
verified = False

if version[0] == 1:
    ca_key = load_pem_public_key(tpm_ca_key, backend=default_backend())
    ica_key = TPMv1.validate_cert(ica_cert, ca_key.public_numbers())
    leaf_key = TPMv1.validate_cert(leaf_cert, ica_key)

    random = Util.random_bytes(8)
    val = etpm.computeSignature(random)
    result = TPMv1.decrypt_block(val, leaf_key)
    if result[80:88] == random:
        verified = True

elif version[0] == 2:
    x509_ca_cert = load_pem_x509_certificate(tpm2_ca_cert, backend=default_backend())
    x509_ica_cert = load_der_x509_certificate(bytes(ica_cert), backend=default_backend())
    x509_leaf_cert = load_der_x509_certificate(bytes(leaf_cert), backend=default_backend())

    if TPMv2.validate_cert([x509_ca_cert], x509_ica_cert) and TPMv2.validate_cert([x509_ca_cert, x509_ica_cert], x509_leaf_cert):
        random = Util.random_bytes(32)
        val = etpm.computeSignature(random)
        verified = TPMv2.verify_signature(val, random, x509_leaf_cert.public_key())

if verified is True:
    print('Signature OK')
