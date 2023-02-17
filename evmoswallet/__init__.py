import coincurve
from coincurve._libsecp256k1 import ffi
from coincurve._libsecp256k1 import lib

from evmoswallet.converter import bech32_to_eth
from evmoswallet.eth.ethereum import HDKey
from evmoswallet.eth.ethereum import HDPrivateKey


class Wallet:
    def __init__(self, seed, prefix, algo='ethsecp256k1') -> None:
        if algo == 'ethsecp256k1':
            master_key = HDPrivateKey.master_key_from_mnemonic(seed)
            root_keys = HDKey.from_path(master_key, "m/44'/60'/0'")

            acct_priv_key = root_keys[-1]

            acct_pub_key = HDKey.from_b58check(acct_priv_key.to_b58check())
            keys = HDKey.from_path(acct_pub_key, f'{0}/{0}')

            self.eth_address = keys[-1].public_key.address()
            self.private_key = bytes.fromhex(keys[-1]._key.to_hex())
            self.evmos_address = bech32_to_eth(self.eth_address, prefix)
            self.public_key = keys[-1].public_key.compressed_bytes
        else:
            # TODO: sopport for secp256k1
            raise NotImplementedError(f'{algo} is not supported!')

    def sign(self, msg: bytes) -> bytes:
        key = coincurve.PrivateKey(self.private_key)
        nonce = (lib.secp256k1_nonce_function_rfc6979, ffi.NULL)
        return key.sign_recoverable(msg, hasher=None, custom_nonce=nonce)
