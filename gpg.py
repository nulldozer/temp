# here's my half-ass gpg packet (rfc4880) serializer
#
# don't use this ever. it won't work. it will ruin your life and get you fired
#
# written by Daniel Kokoszka 2018

import math
import time

def int_to_be_list(num, length=None):
    if(length is None): length = math.ceil(math.log(num, 256))
    be_list = [((num & 0x0ff << i*8) >> i*8) for i in reversed(range(length))]
    return be_list

def int_to_be_bytes(num, length=None):
    return bytes(int_to_be_list(num, length))

def int_to_mpi_bytes(num):
    # rfc4880 says you start counting bits at the most significant nonzero bit down to
    # zeroth bit
    num_bits = math.floor(math.log(num,2))+1
    be_num_bits = int_to_be_bytes(num_bits,2)
    be_num = int_to_be_bytes(num)
    return be_num_bits + be_num

#tag: number - describes the type of packet
#body_length: number - number of octets in the packet (not including header TODO checksum?)
def make_old_header(tag, body_length):
    header = []
    #### First octet "packet tag"
    header.append(0)

    # indicate old header by setting bit 7
    header[0] |= 1 << 7

    # set bits 5-2 to tag
    tag &= 0b01111
    header[0] |= tag << 2

    # set bits 1-0 to number of octets that follow describing length
    # 0 packet has one-octet length
    # 1 packet has two-octet length
    # 2 packet has four-octet length
    # 3 packet has indeterminate length
    lentype = math.floor(math.log(body_length, 256))
    if(lentype > 3): lentype = 3

    # lentype will always fit in 2 bits
    header[0] |= lentype

    ##### Length octets (don't apply when lentype=3)
    if(lentype < 3):
        length_bytes = int_to_be_list(body_length, lentype+1)
        header += length_bytes

    return bytes(header)

def make_secret_key_packet(key):
    body = bytes([])

    # version number
    body += bytes([4])

    # creation time... setting to zeros for deterministic output
    body += bytes([0,0,0,0]) #int_to_be_bytes(int(time.time()), 4)

    # algorithm of this key
    body += bytes([1])

    # public part
    body += int_to_mpi_bytes(key.n)
    body += int_to_mpi_bytes(key.e)

    # indicate that data is not encrypted with a zero
    body += bytes([0])

    # skip the optional stuff

    # private part
    body += int_to_mpi_bytes(key.d)
    body += int_to_mpi_bytes(key.p)
    body += int_to_mpi_bytes(key.q)
    body += int_to_mpi_bytes(key.u)

    # body is done, sum it up
    checksum = int_to_be_bytes(sum(body) % 65536, 2)

    # make and prepend a header
    header = make_old_header(5, len(body))

    packet = header + body + checksum

    return packet

def serialize(key):
    serialized = b''

#https://tools.ietf.org/html/rfc4880#section-5.5.1.3
    # 0x 95 03 98, 04, 5A 9A 
    # packet tag 0x95 (0x05 << 2 | 0x01) means old packet, type 5, two bytes for length
    # length bytes: 03 98


    # Old: Secret Key Packet(tag 5)(920 bytes)
    #    Ver 4 - new
    #    creation time - Sat Mar  3 14:35:12 EST 2018
    #    Pub alg - RSA Encrypt or Sign(pub 1)
    #    RSA n(2048 bits) - ...
    #    RSA e(17 bits) - ...
    #    RSA d(2043 bits) - ...
    #    RSA p(1024 bits) - ...
    #    RSA q(1024 bits) - ...
    #    RSA u(1024 bits) - ...
    #    Checksum - 48 25 

    serialized += make_secret_key_packet(key)

#https://tools.ietf.org/html/rfc4880#section-5.11
    #Old: User ID Packet(tag 13)(24 bytes)
    #    User ID - Dickface <dick@face.com>

#https://tools.ietf.org/html/rfc4880#section-5.2
    #Old: Signature Packet(tag 2)(312 bytes)
    #    Ver 4 - new
    #    Sig type - Positive certification of a User ID and Public Key packet(0x13).
    #    Pub alg - RSA Encrypt or Sign(pub 1)
    #    Hash alg - SHA1(hash 2)
    #    Hashed Sub: signature creation time(sub 2)(4 bytes)
    #        Time - Sat Mar  3 14:35:12 EST 2018
    #    Hashed Sub: key flags(sub 27)(1 bytes)
    #        Flag - This key may be used to certify other keys
    #        Flag - This key may be used to sign data
    #    Hashed Sub: preferred symmetric algorithms(sub 11)(5 bytes)
    #        Sym alg - AES with 256-bit key(sym 9)
    #        Sym alg - AES with 192-bit key(sym 8)
    #        Sym alg - AES with 128-bit key(sym 7)
    #        Sym alg - CAST5(sym 3)
    #        Sym alg - Triple-DES(sym 2)
    #    Hashed Sub: preferred hash algorithms(sub 21)(5 bytes)
    #        Hash alg - SHA256(hash 8)
    #        Hash alg - SHA1(hash 2)
    #        Hash alg - SHA384(hash 9)
    #        Hash alg - SHA512(hash 10)
    #        Hash alg - SHA224(hash 11)
    #    Hashed Sub: preferred compression algorithms(sub 22)(3 bytes)
    #        Comp alg - ZLIB <RFC1950>(comp 2)
    #        Comp alg - BZip2(comp 3)
    #        Comp alg - ZIP <RFC1951>(comp 1)
    #    Hashed Sub: features(sub 30)(1 bytes)
    #        Flag - Modification detection (packets 18 and 19)
    #    Hashed Sub: key server preferences(sub 23)(1 bytes)
    #        Flag - No-modify
    #    Sub: issuer key ID(sub 16)(8 bytes)
    #        Key ID - 0x77863D2728F7E6CC
    #    Hash left 2 bytes - 18 ef 
    #    RSA m^d mod n(2046 bits) - ...
    #        -> PKCS-1

#https://tools.ietf.org/html/rfc4880#section-5.5.3
    #Old: Secret Subkey Packet(tag 7)(920 bytes)
    #    Ver 4 - new
    #    Public key creation time - Sat Mar  3 14:35:12 EST 2018
    #    Pub alg - RSA Encrypt or Sign(pub 1)
    #    RSA n(2048 bits) - ...
    #    RSA e(17 bits) - ...
    #    RSA d(2043 bits) - ...
    #    RSA p(1024 bits) - ...
    #    RSA q(1024 bits) - ...
    #    RSA u(1024 bits) - ...
    #    Checksum - 37 47 

#https://tools.ietf.org/html/rfc4880#section-5.2
    #Old: Signature Packet(tag 2)(287 bytes)
    #    Ver 4 - new
    #    Sig type - Subkey Binding Signature(0x18).
    #    Pub alg - RSA Encrypt or Sign(pub 1)
    #    Hash alg - SHA1(hash 2)
    #    Hashed Sub: signature creation time(sub 2)(4 bytes)
    #        Time - Sat Mar  3 14:35:12 EST 2018
    #    Hashed Sub: key flags(sub 27)(1 bytes)
    #        Flag - This key may be used to encrypt communications
    #        Flag - This key may be used to encrypt storage
    #    Sub: issuer key ID(sub 16)(8 bytes)
    #        Key ID - 0x77863D2728F7E6CC
    #    Hash left 2 bytes - 66 f9 
    #    RSA m^d mod n(2047 bits) - ...
    #        -> PKCS-1

    return serialized
