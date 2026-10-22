#!/usr/bin/env python3
"""Pure-Python reference implementation of Ed25519, Ed25519ph and X25519.

The module uses only the Python standard library (``hashlib`` and ``sys``)
and follows RFC 8032 (Ed25519 and Ed25519ph) and RFC 7748 (X25519) directly.
It is deliberately simple rather than fast; the goal is an independent,
auditable oracle for checking results produced by a hardware implementation.

Run the embedded test vectors with::

    python3 test/ref25519.py selftest
"""

import hashlib
import sys

__all__ = [
    "ed25519_public_key",
    "ed25519_sign",
    "ed25519_verify",
    "ed25519ph_sign",
    "ed25519ph_verify",
    "x25519",
    "x25519_public_key",
]

# p = 2^255 - 19, the field prime.
P = 2**255 - 19

# L, the order of the Ed25519 base point (and of its prime-order subgroup).
L = 2**252 + 27742317777372353535851937790883648493

# d = -121665 / 121666 mod p, the twisted Edwards curve constant.
D = (-121665 * pow(121666, P - 2, P)) % P
D2 = (2 * D) % P

# A square root of -1 modulo p.
SQRT_M1 = pow(2, (P - 1) // 4, P)

# dom2 prefix for Ed25519ph: "SigEd25519 no Ed25519 collisions", phflag = 1,
# and an empty context (the context length is the final zero byte).
DOM2 = b"SigEd25519 no Ed25519 collisions" + b"\x01\x00"

# Projective identity in extended coordinates (X : Y : Z : T).
IDENTITY = (0, 1, 1, 0)


# ---------------------------------------------------------------------------
# Byte input handling
# ---------------------------------------------------------------------------

def _coerce_bytes(name, value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise TypeError("%s must be bytes-like" % name)


def _check_length(name, value, expected):
    if len(value) != expected:
        raise ValueError(
            "%s must be %d bytes, got %d" % (name, expected, len(value))
        )


def _sha512(*parts):
    digest = hashlib.sha512()
    for part in parts:
        digest.update(part)
    return digest.digest()


def _hash_to_scalar(digest32):
    """Clamp a 32-byte hash for use as an Ed25519 secret scalar."""
    scalar = bytearray(digest32)
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return int.from_bytes(scalar, "little")


# ---------------------------------------------------------------------------
# Twisted Edwards group operations (extended coordinates)
#
# A point (X : Y : Z : T) represents the affine point (X/Z, Y/Z), with
# T = X*Y/Z, on -x^2 + y^2 = 1 + d*x^2*y^2.
# ---------------------------------------------------------------------------

def _point_add(p, q):
    """Add two extended points.  Complete for a = -1 and non-square d."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q

    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = D2 * t1 * t2 % P
    d = 2 * z1 * z2 % P
    e = (b - a) % P
    f = (d - c) % P
    g = (d + c) % P
    h = (b + a) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _point_double(p):
    """Double an extended point (formula specialized for a = -1)."""
    x1, y1, z1, _ = p

    a = x1 * x1 % P
    b = y1 * y1 % P
    c = 2 * z1 * z1 % P
    d = -a % P
    e = ((x1 + y1) * (x1 + y1) - a - b) % P
    g = (d + b) % P
    f = (g - c) % P
    h = (d - b) % P
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _point_mul(scalar, point):
    """Multiply a point by a non-negative integer (double-and-add)."""
    result = IDENTITY
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_double(addend)
        scalar >>= 1
    return result


def _point_encode(point):
    """Encode a point as 32 bytes: y, with the low bit of x in bit 255."""
    x, y, z, _ = point
    z_inverse = pow(z, P - 2, P)
    x = x * z_inverse % P
    y = y * z_inverse % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _recover_x(y, sign):
    """Recover the x-coordinate for a given y and sign bit.

    Raises ValueError when no such point exists (or when x = 0 and the sign
    bit is set, which is a non-canonical encoding).
    """
    y2 = y * y % P
    u = (y2 - 1) % P
    v = (D * y2 + 1) % P
    if v == 0:
        raise ValueError("invalid point encoding: division by zero")
    x2 = u * pow(v, P - 2, P) % P

    if x2 == 0:
        if sign:
            raise ValueError("invalid point encoding: x = 0 with sign bit set")
        return 0

    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        raise ValueError("invalid point encoding: not a square")

    if (x & 1) != sign:
        x = (P - x) % P
    return x


def _point_decode(data):
    """Decode and validate a 32-byte compressed Edwards point."""
    if len(data) != 32:
        raise ValueError("point encoding must be 32 bytes")

    encoded = int.from_bytes(data, "little")
    sign = (encoded >> 255) & 1
    y = encoded & ((1 << 255) - 1)
    if y >= P:
        raise ValueError("invalid point encoding: y is not canonical")

    x = _recover_x(y, sign)
    return (x, y, 1, x * y % P)


# The Ed25519 base point B has y = 4/5 and an even x-coordinate.
_BASE_Y = 4 * pow(5, P - 2, P) % P
_BASE_X = _recover_x(_BASE_Y, 0)
BASE = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % P)


# ---------------------------------------------------------------------------
# Ed25519 / Ed25519ph
# ---------------------------------------------------------------------------

def _derive_public_key(seed):
    hashed = _sha512(seed)
    scalar = _hash_to_scalar(hashed[:32])
    return _point_encode(_point_mul(scalar, BASE))


def _sign(seed, message, dom2):
    hashed = _sha512(seed)
    scalar = _hash_to_scalar(hashed[:32])
    prefix = hashed[32:]

    public_key = _point_encode(_point_mul(scalar, BASE))

    r = int.from_bytes(_sha512(dom2, prefix, message), "little") % L
    encoded_r = _point_encode(_point_mul(r, BASE))

    k = int.from_bytes(
        _sha512(dom2, encoded_r, public_key, message), "little"
    ) % L
    s = (r + k * scalar) % L

    return encoded_r + s.to_bytes(32, "little")


def _verify(public_key, message, signature, dom2):
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False

    try:
        a = _point_decode(public_key)
        r = _point_decode(signature[:32])
    except ValueError:
        return False

    k = int.from_bytes(
        _sha512(dom2, signature[:32], public_key, message), "little"
    ) % L

    left = _point_mul(s, BASE)
    right = _point_add(r, _point_mul(k, a))
    return _point_encode(left) == _point_encode(right)


def ed25519_public_key(seed: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public key from a 32-byte seed."""
    seed = _coerce_bytes("seed", seed)
    _check_length("seed", seed, 32)
    return _derive_public_key(seed)


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    """Sign ``message`` with Ed25519; returns R || S (64 bytes)."""
    seed = _coerce_bytes("seed", seed)
    message = _coerce_bytes("message", message)
    _check_length("seed", seed, 32)
    return _sign(seed, message, b"")


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature.

    Returns False for malformed or invalid signatures.  Only wrong-length
    inputs raise ValueError.
    """
    public_key = _coerce_bytes("public_key", public_key)
    message = _coerce_bytes("message", message)
    signature = _coerce_bytes("signature", signature)
    _check_length("public_key", public_key, 32)
    _check_length("signature", signature, 64)
    return _verify(public_key, message, signature, b"")


def ed25519ph_sign(seed: bytes, prehash: bytes) -> bytes:
    """Sign a 64-byte SHA-512 prehash with Ed25519ph.

    ``prehash`` must be PH(M) = SHA-512(M), exactly 64 bytes.
    """
    seed = _coerce_bytes("seed", seed)
    prehash = _coerce_bytes("prehash", prehash)
    _check_length("seed", seed, 32)
    _check_length("prehash", prehash, 64)
    return _sign(seed, prehash, DOM2)


def ed25519ph_verify(public_key: bytes, prehash: bytes, signature: bytes) -> bool:
    """Verify an Ed25519ph signature over a 64-byte SHA-512 prehash."""
    public_key = _coerce_bytes("public_key", public_key)
    prehash = _coerce_bytes("prehash", prehash)
    signature = _coerce_bytes("signature", signature)
    _check_length("public_key", public_key, 32)
    _check_length("prehash", prehash, 64)
    _check_length("signature", signature, 64)
    return _verify(public_key, prehash, signature, DOM2)


# ---------------------------------------------------------------------------
# X25519 (RFC 7748)
# ---------------------------------------------------------------------------

def x25519(scalar: bytes, u: bytes) -> bytes:
    """Compute X25519(scalar, u), returning the 32-byte u-coordinate.

    The scalar is clamped and the most significant bit of ``u`` is masked,
    as required by RFC 7748.
    """
    scalar = _coerce_bytes("scalar", scalar)
    u = _coerce_bytes("u", u)
    _check_length("scalar", scalar, 32)
    _check_length("u", u, 32)

    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k_int = int.from_bytes(k, "little")

    # Mask bit 255 and process the value modulo p (non-canonical inputs are
    # expressly allowed by RFC 7748).
    u_int = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x1 = u_int % P

    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0

    for bit in range(254, -1, -1):
        k_bit = (k_int >> bit) & 1
        swap ^= k_bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_bit

        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P

        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + 121665 * e) % P

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2

    result = x2 * pow(z2, P - 2, P) % P
    return result.to_bytes(32, "little")


def x25519_public_key(scalar: bytes) -> bytes:
    """Compute the X25519 public key X25519(scalar, 9)."""
    scalar = _coerce_bytes("scalar", scalar)
    _check_length("scalar", scalar, 32)
    return x25519(scalar, b"\x09" + b"\x00" * 31)


# ---------------------------------------------------------------------------
# Embedded RFC test vectors
# ---------------------------------------------------------------------------

# BEGIN RFC 8032 VECTORS
_RFC8032_VECTORS = (
    (
        "RFC 8032 7.1 TEST 1",
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "RFC 8032 7.1 TEST 2",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "RFC 8032 7.1 TEST 3",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    (
        "RFC 8032 7.1 TEST 1024",
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
        "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
    ),
    (
        "RFC 8032 7.1 TEST SHA(abc)",
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    ),
)

_ED25519PH_VECTOR = (
    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
    "616263",
    "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406",
)
# END RFC 8032 VECTORS

# RFC 7748, section 5.2: (scalar, u-coordinate, output u-coordinate).
_RFC7748_X25519_VECTORS = (
    (
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    ),
    (
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
    ),
)

# RFC 7748, section 6.1.
_RFC7748_ALICE_PRIVATE = (
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
)
_RFC7748_ALICE_PUBLIC = (
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
)
_RFC7748_BOB_PRIVATE = (
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
)
_RFC7748_BOB_PUBLIC = (
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
)
_RFC7748_SHARED = (
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _format_value(value):
    if isinstance(value, bytes):
        return value.hex()
    return repr(value)


def _run_selftest():
    failures = []

    def check(name, expected, actual):
        if expected != actual:
            failures.append((name, expected, actual))

    for name, seed_hex, public_hex, message_hex, signature_hex in (
        _RFC8032_VECTORS
    ):
        seed = bytes.fromhex(seed_hex)
        public_key = bytes.fromhex(public_hex)
        message = bytes.fromhex(message_hex)
        signature = bytes.fromhex(signature_hex)

        check(name + ": public key", public_key, ed25519_public_key(seed))
        check(name + ": signature", signature, ed25519_sign(seed, message))
        check(
            name + ": verification",
            True,
            ed25519_verify(public_key, message, signature),
        )

        tampered = bytearray(signature)
        tampered[0] ^= 1
        check(
            name + ": reject tampered signature",
            False,
            ed25519_verify(public_key, message, bytes(tampered)),
        )
        check(
            name + ": reject altered message",
            False,
            ed25519_verify(public_key, message + b"\x00", signature),
        )

    seed_hex, public_hex, message_hex, signature_hex = _ED25519PH_VECTOR
    seed = bytes.fromhex(seed_hex)
    public_key = bytes.fromhex(public_hex)
    message = bytes.fromhex(message_hex)
    prehash = hashlib.sha512(message).digest()
    signature = bytes.fromhex(signature_hex)

    check("RFC 8032 7.3 Ed25519ph TEST abc: public key", public_key,
          ed25519_public_key(seed))
    check("RFC 8032 7.3 Ed25519ph TEST abc: signature", signature,
          ed25519ph_sign(seed, prehash))
    check("RFC 8032 7.3 Ed25519ph TEST abc: verification", True,
          ed25519ph_verify(public_key, prehash, signature))
    tampered = bytearray(signature)
    tampered[0] ^= 1
    check("RFC 8032 7.3 Ed25519ph TEST abc: reject tampered signature", False,
          ed25519ph_verify(public_key, prehash, bytes(tampered)))

    for index, (scalar_hex, u_hex, output_hex) in enumerate(
        _RFC7748_X25519_VECTORS, 1
    ):
        check(
            "RFC 7748 5.2 X25519 vector %d" % index,
            bytes.fromhex(output_hex),
            x25519(bytes.fromhex(scalar_hex), bytes.fromhex(u_hex)),
        )

    alice_private = bytes.fromhex(_RFC7748_ALICE_PRIVATE)
    alice_public = bytes.fromhex(_RFC7748_ALICE_PUBLIC)
    bob_private = bytes.fromhex(_RFC7748_BOB_PRIVATE)
    bob_public = bytes.fromhex(_RFC7748_BOB_PUBLIC)
    shared = bytes.fromhex(_RFC7748_SHARED)

    check("RFC 7748 6.1 Alice public key", alice_public,
          x25519_public_key(alice_private))
    check("RFC 7748 6.1 Bob public key", bob_public,
          x25519_public_key(bob_private))
    check("RFC 7748 6.1 Alice/Bob shared secret", shared,
          x25519(alice_private, bob_public))
    check("RFC 7748 6.1 Bob/Alice shared secret", shared,
          x25519(bob_private, alice_public))

    if failures:
        for name, expected, actual in failures:
            print("FAIL: " + name)
            print("  expected: " + _format_value(expected))
            print("  actual:   " + _format_value(actual))
        return 1

    print("OK")
    return 0


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

_USAGE = "usage: python3 test/ref25519.py selftest"


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)

    if not args or args in (["-h"], ["--help"]):
        print(_USAGE)
        return 0

    if args == ["selftest"]:
        return _run_selftest()

    print(_USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main())
