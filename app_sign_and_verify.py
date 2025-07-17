from eth_account import Account
from web3 import Web3
from eth_keys import keys
from eth_utils import decode_hex


def compute_msg_hash(sign_params: str)->bytes:
    # 1. keccak256 of the message (as bytes)
    message_hash = "0x"+Web3.keccak(text=sign_params).hex()
    # print("hash:", message_hash)
    prefix = "\u0019Ethereum Signed Message:\n" + str(len(message_hash))
    to_sign = (prefix + message_hash).encode("utf-8")
    msg_hash = Web3.keccak(to_sign)
    # print("msgHash:", msg_hash.hex())
    return msg_hash

def sign_message(app_secret: str, sign_params: str) -> str:
    msg_hash = compute_msg_hash(sign_params)
    pk = keys.PrivateKey(decode_hex(app_secret))
    signature = pk.sign_msg_hash(msg_hash)
    return signature.to_bytes().hex()


def verify_signature(sign_params: str, signature: str) -> str:
    msg_hash = compute_msg_hash(sign_params)
    # log msg_hash
    print("msgHash:", msg_hash.hex())
    sig_bytes = bytes.fromhex(signature[2:] if signature.startswith('0x') else signature)
    sig_obj = keys.Signature(sig_bytes)
    pk = keys.ecdsa_recover(msg_hash, sig_obj)
    return pk.to_checksum_address()


if __name__ == '__main__':
    # Example usage
    # Replace with your own app secret, this key just for test: appId->0x811169961c2949e8c91e7840c5452cc4deb1942c
    private_key = "0x7e1ed873b1dae173efaf9b00b79cd6567a828cb3385ddc2d173ec161c23a3496"
    # !!!Notice: sign_params is a string not object
    sign_params = "{\"appId\":\"0x811169961c2949e8c91e7840c5452cc4deb1942c\",\"attTemplateID\":\"2e3160ae-8b1e-45e3-8c59-426366278b9d\",\"userAddress\":\"0xB12a1f7035FdCBB4cC5Fa102C01346BD45439Adf\",\"timestamp\":1752730452083,\"attMode\":{\"algorithmType\":\"proxytls\",\"resultType\":\"plain\"}}"
    print("sign_params:", sign_params)
    sig = sign_message(private_key, sign_params)
    print("Signature:", "0x"+sig)
    recovered = verify_signature(sign_params, sig)
    print("Recovered appId:", recovered)
