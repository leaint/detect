import hashlib
import struct
import time
import hmac

# 部分源代码来自 DavidBuchanan314/ScapyGuard
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

server_public = '6e65ce0be17517110c17d77288ad87e7fd5252dcc7d09b95a39d61db03df832a'

# 配置文件中的private_key字段
client_private = ''

CONSTRUCTION = b'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s'
IDENTIFIER = b'WireGuard v1 zx2c4 Jason@zx2c4.com'
LABEL_MAC1 = b'mac1----'
LABEL_COOKIE = b'cookie--'

responder = {
    'static_public': bytes.fromhex(server_public)
}

def HASH(data: bytes):
    return hashlib.blake2s(data).digest()

def HMAC(key: bytes, data: bytes):
    return hmac.new(key, data, hashlib.blake2s).digest()

def AEAD(key: bytes, ctr: int, msg: bytes, authtxt: bytes = b""):
    nonce = bytes(4) + ctr.to_bytes(8, "little")
    return ChaCha20Poly1305(key).encrypt(nonce, msg, authtxt)

def TAI64N():
    timestamp = time.time()
    seconds = int(timestamp) + (2 ** 62) + 10
    nanoseconds = int((timestamp % 1) * 1e6)
    return struct.pack(">QI", seconds, nanoseconds)

def MAC(key: bytes, data: bytes):
    return hashlib.blake2s(data, digest_size=16, key=key).digest()


initiator: dict[str, bytes] = {}

static_private = X25519PrivateKey.from_private_bytes(
    bytes.fromhex(client_private))

initiator['static_private'] = bytes.fromhex(client_private)
initiator['static_public'] = static_private.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)

initiator['chaining_key'] = HASH(CONSTRUCTION)
initiator['hash'] = HASH(
    HASH(initiator['chaining_key'] + IDENTIFIER) + responder['static_public'])
ephemeral_private = X25519PrivateKey.generate()

unencrypted_ephemeral = ephemeral_private.public_key()

msg = {
    'message_type': b'\x01',
    'reserved_zero': b'\x00\x00\x00',
    'sender_index': (1).to_bytes(32//8, 'little'),
    'unencrypted_ephemeral': unencrypted_ephemeral.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
}

initiator['hash'] = HASH(initiator['hash'] + msg['unencrypted_ephemeral'])

temp = HMAC(initiator['chaining_key'], msg['unencrypted_ephemeral'])
initiator['chaining_key'] = HMAC(temp, b'\x01')

temp = HMAC(initiator['chaining_key'], ephemeral_private.exchange(
    X25519PublicKey.from_public_bytes(responder['static_public'])))
initiator['chaining_key'] = HMAC(temp, b'\x01')
key = HMAC(temp, initiator['chaining_key'] + b'\x02')

msg['encrypted_static'] = AEAD(
    key, 0, initiator['static_public'], initiator['hash'])
initiator['hash'] = HASH(initiator['hash'] + msg['encrypted_static'])

temp = HMAC(initiator['chaining_key'], static_private.exchange(
    X25519PublicKey.from_public_bytes(responder['static_public'])))
initiator['chaining_key'] = HMAC(temp, b'\x01')
key = HMAC(temp, initiator['chaining_key'] + b'\x02')

msg['encrypted_timestamp'] = AEAD(key, 0, TAI64N(), initiator['hash'])

initiator['hash'] = HASH(initiator['hash'] + msg['encrypted_timestamp'])

msg['mac1'] = MAC(HASH(LABEL_MAC1 + responder['static_public']), msg['message_type']+msg['reserved_zero'] +
                  msg['sender_index']+msg['unencrypted_ephemeral']+msg['encrypted_static']+msg['encrypted_timestamp'])
msg['mac2'] = b'\x00' * 16


packet = msg['message_type']+msg['reserved_zero'] + \
    msg['sender_index']+msg['unencrypted_ephemeral']+msg['encrypted_static']+msg['encrypted_timestamp'] +\
    msg['mac1'] + msg['mac2']

for i in packet:
    print(i, end=',')

with open('key.go', 'w') as key_file:
    key_file.write('package main\n\nvar packet []byte = []byte{\n')
    for i in packet:
        key_file.write(f'{i},')
    key_file.write('\n}\n')
