# coding:utf-8

import hashlib


class EncodingError(Exception):
    pass


class BTCValid(object):

    BASE58_ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    BASE58_BASE = len(BASE58_ALPHABET)
    BASE58_LOOKUP = dict((c, i) for i, c in enumerate(BASE58_ALPHABET))

    @staticmethod
    def double_sha256(data):
        """A standard compound hash."""
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    @staticmethod
    def to_long(base, lookup_f, s):
        """
        Convert an array to a (possibly bignum) integer, along with a prefix value
        of how many prefixed zeros there are.

        base:
            the source base
        lookup_f:
            a function to convert an element of s to a value between 0 and base-1.
        s:
            the value to convert
        """
        prefix = 0
        v = 0
        for c in s:
            v *= base
            try:
                v += lookup_f(c)
            except Exception:
                raise EncodingError("bad character %s in string %s" % (c, s))
            if v == 0:
                prefix += 1
        return v, prefix

    @staticmethod
    def from_long(v, prefix, base, charset):
        """The inverse of to_long. Convert an integer to an arbitrary base.

        v: the integer value to convert
        prefix: the number of prefixed 0s to include
        base: the new base
        charset: an array indicating what printable character to use for each value.
        """
        l = bytearray()
        while v > 0:
            try:
                v, mod = divmod(v, base)
                l.append(charset(mod))
            except Exception:
                raise EncodingError("can't convert to character corresponding to %d" % mod)
        l.extend([charset(0)] * prefix)
        l.reverse()
        return bytes(l)

    @classmethod
    def a2b_base58(cls, s):
        """Convert base58 to binary using BASE58_ALPHABET."""
        v, prefix = cls.to_long(cls.BASE58_BASE, lambda c: cls.BASE58_LOOKUP[c], s.encode("utf8"))
        return cls.from_long(v, prefix, 256, lambda x: x)

    @classmethod
    def a2b_hashed_base58(cls, s):
        """
        If the passed string is hashed_base58, return the binary data.
        Otherwise raises an EncodingError.
        """
        data = cls.a2b_base58(s)
        data, the_hash = data[:-4], data[-4:]
        if cls.double_sha256(data)[:4] == the_hash:
            return data
        raise EncodingError("hashed base58 has bad checksum %s" % s)

    @classmethod
    def bitcoin_address_to_hash160_sec_with_prefix(cls, bitcoin_address):
        """
        Convert a Bitcoin address back to the hash160_sec format and
        also return the prefix.
        """
        blob = cls.a2b_hashed_base58(bitcoin_address)
        if len(blob) != 21:
            raise EncodingError("incorrect binary length (%d) for Bitcoin address %s" %
                                (len(blob), bitcoin_address))
        if blob[:1] not in [b'\x6f', b'\0']:
            raise EncodingError("incorrect first byte (%s) for Bitcoin address %s" % (blob[0], bitcoin_address))
        return blob[1:], blob[:1]

    @classmethod
    def is_valid_bitcoin_address(cls, bitcoin_address, allowable_prefixes=b'\0'):
        """Return True if and only if bitcoin_address is valid."""
        try:
            hash160, prefix = cls.bitcoin_address_to_hash160_sec_with_prefix(bitcoin_address)
        except EncodingError:
            return False
        return prefix in allowable_prefixes


if __name__=="__main__":
    print BTCValid.is_valid_bitcoin_address("1Q1pE5vPGEEMqRcVRMbtBdK84Y6Pzo6nK")