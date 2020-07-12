from operator import mod

from Crypto.Util.number import inverse, getStrongPrime


class PrivateKey:
    def __init__(self, d: int, n: int):
        self.d = d  # private exponent
        self.n = n  # modulus


class PublicKey:
    def __init__(self, e: int, n: int):
        self.e = e  # public exponent
        self.n = n  # modulus


class RsaKeyGenerator:

    def __init__(self, key_size: int):
        if key_size not in (1024, 2048, 3072, 4096):
            raise ValueError("unsupported key size")

        if key_size == 1024:
            print("insecure key size equivalent to 80 bit symmetric key")

        self.key_size = key_size

    def generate_keys(self) -> (PrivateKey, PublicKey):
        e = 65537  # standard value for public exponent e
        p, q, n = self._get_exponents_and_modulus(e)

        phi = (p - 1) * (q - 1)
        d = inverse(e, phi)
        print("d: %s" % d)

        if not n.bit_length() - 6 <= d.bit_length() <= n.bit_length():
            raise ValueError("d bit length (%s) should be less than but close to n bit length (%s)" %
                             (d.bit_length(), n.bit_length()))

        if not mod(d * e, phi) == 1:
            raise ValueError("sanity check failed. d*e: %s, phi: %s" % (d * e, phi))

        priv_key = PrivateKey(d, n)
        pub_key = PublicKey(e, n)
        return priv_key, pub_key

    def _get_exponents_and_modulus(self, e: int):
        prime_size = int(self.key_size / 2)
        p = getStrongPrime(prime_size, e)
        q = getStrongPrime(prime_size, e)

        if p == q:
            raise ValueError("p and q are the same")

        n = p * q
        print("p: %s\nq: %s\nn: %s" % (p, q, n))

        if n.bit_length() != self.key_size:
            raise ValueError("modulus not of expected size. key size: %s, modulus bit length: %s" %
                             (self.key_size, n.bit_length()))

        return p, q, n


class RsaEncryptor:
    @staticmethod
    def encrypt(message: int, pub_key: PublicKey) -> int:
        return pow(message, pub_key.e, pub_key.n)

    @staticmethod
    def decrypt(ciphertext: int, priv_key: PrivateKey) -> int:
        return pow(ciphertext, priv_key.d, priv_key.n)


rsa_key_size = 2048
private_key, public_key = RsaKeyGenerator(rsa_key_size).generate_keys()

plaintext = 254234
encrypted_message = RsaEncryptor.encrypt(plaintext, public_key)
decrypted_message = RsaEncryptor.decrypt(encrypted_message, private_key)

if plaintext != decrypted_message:
    raise ValueError("plaintext != decrypted")

print("plaintext: %s\nencrypted: %s\ndecrypted: %s" %
      (plaintext, encrypted_message, decrypted_message))
