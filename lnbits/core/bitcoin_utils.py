# lnbits/core/bitcoin_utils.py
import hashlib
import base64
from ecdsa import VerifyingKey, SECP256k1, util
from ecdsa.util import sigdecode_der
from typing import Union

from loguru import logger

def verify_bitcoin_message(address: str, signature: str, message: str, public_key_hex: str) -> bool:
    try:
        logger.info(f"Verifying message: '{message}' for address: {address}")

        # Verify that the public key corresponds to the address
        derived_address = pubkey_to_address(public_key_hex)
        if derived_address != address:
            logger.error("Provided public key does not correspond to the provided address.")
            return False
        else:
            logger.info("Public key corresponds to the address.")

        # Decode the signature from base64
        sig_bytes = base64.b64decode(signature)

        logger.info(f"Signature length: {len(sig_bytes)}")
        logger.info(f"Raw signature bytes: {sig_bytes.hex()}")

        # The signature includes the recovery ID; strip it off
        recovery_id = sig_bytes[0]
        sig_bytes = sig_bytes[1:]

        logger.info(f"Recovery ID: {recovery_id}")
        logger.info(f"Signature length after stripping recovery ID: {len(sig_bytes)}")

        if len(sig_bytes) != 64:
            logger.error(f"Invalid signature length after stripping recovery ID: {len(sig_bytes)}")
            return False

        # Split the signature into r and s
        r = int.from_bytes(sig_bytes[:32], byteorder='big')
        s = int.from_bytes(sig_bytes[32:], byteorder='big')

        # Encode r and s into DER format
        der_sig = util.sigencode_der(r, s, SECP256k1.order)

        logger.info(f"DER-encoded signature length: {len(der_sig)}")

        # Prepare the message (Bitcoin signed message format)
        message_magic = b"\x18Bitcoin Signed Message:\n"
        message_bytes = message.encode('utf-8')
        message_to_hash = message_magic + encode_varint(len(message_bytes)) + message_bytes

        # Double SHA256 hash the message
        message_hash = hashlib.sha256(hashlib.sha256(message_to_hash).digest()).digest()

        logger.info(f"Message hash: {message_hash.hex()}")

        # Create verifying key from public key
        public_key_bytes = bytes.fromhex(public_key_hex)
        pk = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)

        # Verify the signature
        verified = pk.verify_digest(der_sig, message_hash, sigdecode=util.sigdecode_der)
        logger.info(f"Signature verification result: {verified}")
        return verified
    except Exception as e:
        logger.error(f"Signature verification error: {str(e)}")
        return False

def encode_varint(i: int) -> bytes:
    if i < 0xfd:
        return i.to_bytes(1, 'big')
    elif i <= 0xffff:
        return b'\xfd' + i.to_bytes(2, 'little')
    elif i <= 0xffffffff:
        return b'\xfe' + i.to_bytes(4, 'little')
    else:
        return b'\xff' + i.to_bytes(8, 'little')

def encode_varint(i: int) -> bytes:
    if i < 0xfd:
        return i.to_bytes(1, 'little')
    elif i <= 0xffff:
        return b'\xfd' + i.to_bytes(2, 'little')
    elif i <= 0xffffffff:
        return b'\xfe' + i.to_bytes(4, 'little')
    else:
        return b'\xff' + i.to_bytes(8, 'little')

def pubkey_to_address(public_key: Union[bytes, str]) -> str:
    if isinstance(public_key, str):
        public_key = bytes.fromhex(public_key)
    
    sha256 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256)
    pubkey_hash = ripemd160.digest()
    
    version = b'\x00'  # Mainnet
    payload = version + pubkey_hash
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    
    address_bytes = payload + checksum
    return '1' + base58_encode(address_bytes)  # Add leading '1'

def base58_encode(data: bytes) -> str:
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = int.from_bytes(data, 'big')
    result = ''
    while n > 0:
        n, r = divmod(n, 58)
        result = alphabet[r] + result
    return result