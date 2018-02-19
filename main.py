from pbkdf2 import crypt
import argparse

def generate_mnemonic():
    pass

def mnemonic_to_seed():
    pass

def make_rsa_key(seed):
    # seed the RNG with the seed provided
    # use a library to generate an RSA key, tell it to use the RND
    pass

def write_rsa_key(filename):
    # do gpg shit
    pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Convert between mnemonic phrase and gpg rsa key')
    parser.add_argument('--generate-new', action='store_true')
    args = parser.parse_args()
    print(args)

    if args.generate_new:
        print('generating new')
        # get a random number from the system's RNG
        # convert the number to a mnemonic
    else:
        print('waiting for mnemonic phrase from stdin')
