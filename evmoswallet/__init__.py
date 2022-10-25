import coincurve
from coincurve._libsecp256k1 import ffi
from coincurve._libsecp256k1 import lib

from evmoswallet.converter import eth_to_evmos
from evmoswallet.eth.ethereum import HDKey
from evmoswallet.eth.ethereum import HDPrivateKey


class Wallet:
    def __init__(self, seed, algo='ethsecp256k1') -> None:
        if algo == 'ethsecp256k1':
            master_key = HDPrivateKey.master_key_from_mnemonic(seed)
            root_keys = HDKey.from_path(master_key, "m/44'/60'/0'")

            acct_priv_key = root_keys[-1]

            acct_pub_key = HDKey.from_b58check(acct_priv_key.to_b58check())
            keys = HDKey.from_path(acct_pub_key, f'{0}/{0}')

            self.eth_address = keys[-1].public_key.address()
            self.private_key = bytes.fromhex(keys[-1]._key.to_hex())
            self.evmos_address = eth_to_evmos(self.eth_address)
            self.public_key = keys[-1].public_key.compressed_bytes
        else:
            # TODO: sopport for secp256k1
            raise NotImplementedError(f'{algo} is not supported!')

    def sign(self, msg: bytes) -> bytes:
        key = coincurve.PrivateKey(self.private_key)

        nonce = (lib.secp256k1_nonce_function_rfc6979, ffi.NULL)

        
        #return key.sign_recoverable(msg, hasher=None, custom_nonce=nonce)
        #from web3.auto import w3
        #return w3.eth.account.sign_message(msg, private_key=self.private_key)

        from bitcoin import ecdsa_raw_sign
        from bitcoin import der_encode_sig
        from evmoswallet.eth.ethereum import sha3_256

        return bytes(der_encode_sig(*ecdsa_raw_sign(sha3_256(msg).digest(), self.private_key)), 'utf-8')