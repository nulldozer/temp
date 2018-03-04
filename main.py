import argparse, random
from Cryptodome.PublicKey import RSA
from getpass import getpass

from mnemonic import Mnemonic
import gpg

def generate_rsa_key(bits, prng_seed):
    random.seed(prng_seed)
    pseudorandom_bytes = lambda n: bytes([random.randrange(0,255) for i in range(n)])
    return RSA.generate(bits, pseudorandom_bytes)

def main():
    parser = argparse.ArgumentParser(description='Convert between mnemonic phrase and gpg rsa key')
    parser.add_argument('--generate-new', action='store_true')
    parser.add_argument('--bits', default=2048, type=int)
    parser.add_argument('--lang')
    args = parser.parse_args()

    try:
        m = Mnemonic(args.lang)
    except Exception as e:
        print('Error:', str(e))
        return

    if args.generate_new:
        phrase = m.make_seed()
        prng_seed = m.mnemonic_decode(phrase)

    else:
        phrase = getpass('Enter mnemonic phrase:')
        prng_seed = m.mnemonic_decode(phrase)

    print('phrase:\n',phrase)
    print('prng_seed:\n',prng_seed)
    key = generate_rsa_key(args.bits, prng_seed)

    #TODO
    #TODO
    #TODO serialize in pgp export format
    #TODO
    #TODO

    # gpg serialization info
    # https://tools.ietf.org/html/rfc4880#section-4

    # pycryptodomex docs
    # https://www.pycryptodome.org/en/latest/src/public_key/rsa.html#Crypto.PublicKey.RSA.generate

    gpg_key = gpg.serialize(key)

    print('gpg_key\n',' '.join(['%02X' % char for char in gpg_key]))

    key.exportKey(format='PEM')
    key.exportKey(format='DER')

if __name__ == '__main__':
    main()
