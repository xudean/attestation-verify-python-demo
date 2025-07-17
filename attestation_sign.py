import json
from dataclasses import dataclass
from typing import List
from web3 import Web3
from eth_keys import keys

@dataclass
class AttNetworkRequest:
    url: str
    header: str
    method: str
    body: str

@dataclass
class AttNetworkResponseResolve:
    keyName: str
    parseType: str
    parsePath: str

@dataclass
class Attestor:
    attestorAddr: str
    url: str

@dataclass
class Attestation:
    recipient: str
    request: AttNetworkRequest
    reponseResolve: List[AttNetworkResponseResolve]
    data: str
    attConditions: str
    timestamp: int
    additionParams: str
    attestors: List[Attestor]
    signatures: List[str]

def encode_string_packed(s: str) -> bytes:
    return s.encode('utf-8')

def encode_bytes_packed(b: bytes) -> bytes:
    return b

def encode_req(req: AttNetworkRequest) -> str:
    hash_hex = Web3.solidity_keccak(
        ['string', 'string', 'string', 'string'],
        [req.url, req.header, req.method, req.body]
    ).hex()
    print("attNetworkRequest:", hash_hex)
    return hash_hex

def encode_rsp(resolves: List[AttNetworkResponseResolve]) -> str:
    encode_data = b''
    for resolve in resolves:
        # 1. encode DynamicBytes
        encoded_dynamic = encode_bytes_packed(encode_data)
        # 2. encode string fields
        encoded_key = encode_string_packed(resolve.keyName)
        encoded_type = encode_string_packed(resolve.parseType)
        encoded_path = encode_string_packed(resolve.parsePath)
        # 3. concatenate
        temp_encode_data = b''
        if len(encode_data) > 0:
            trimmed = encoded_dynamic[:len(encode_data)]
            temp_encode_data += trimmed
        temp_encode_data += encoded_key
        temp_encode_data += encoded_type
        temp_encode_data += encoded_path
        encode_data = temp_encode_data
    print("attNetworkResponse encodeData:", encode_data.hex())
    hash_hex = Web3.keccak(encode_data).hex()
    print("attNetworkResponse:", hash_hex)
    return hash_hex

def encode_attestation(att: Attestation) -> str:
    from eth_utils import to_canonical_address
    # 1. address
    recipient_bytes = to_canonical_address(att.recipient)
    recipient_hex = recipient_bytes.hex()
    # 2. bytes32
    req_hash = bytes.fromhex(encode_req(att.request))
    req_hash_hex = req_hash.hex()
    rsp_hash = bytes.fromhex(encode_rsp(att.reponseResolve))
    rsp_hash_hex = rsp_hash.hex()
    # 3. string
    data_bytes = att.data.encode('utf-8')
    data_hex = data_bytes.hex()
    att_conditions_bytes = att.attConditions.encode('utf-8')
    att_conditions_hex = att_conditions_bytes.hex()
    addition_params_bytes = att.additionParams.encode('utf-8')
    addition_params_hex = addition_params_bytes.hex()
    # 4. uint64
    timestamp_bytes = att.timestamp.to_bytes(8, byteorder='big')
    timestamp_hex = timestamp_bytes.hex()
    # 5. concatenate all hex strings
    packed_hex = (
        recipient_hex +
        req_hash_hex +
        rsp_hash_hex +
        data_hex +
        att_conditions_hex +
        timestamp_hex +
        addition_params_hex
    )
    # 6. add 0x prefix
    packed_hex = '0x' + packed_hex
    # 7. convert to bytes
    packed_bytes = bytes.fromhex(packed_hex[2:])
    # 8. keccak256
    encode_hash = Web3.keccak(packed_bytes).hex()
    return encode_hash

def hex_to_bytes(hex_str: str) -> bytes:
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    return bytes.fromhex(hex_str)

def recover_address(hash_hex: str, signature: str) -> str:
    sig_bytes = hex_to_bytes(signature)
    message_hash = hex_to_bytes(hash_hex)

    if len(sig_bytes) != 65:
        raise ValueError(f"Signature length is {len(sig_bytes)}, expected 65 bytes")

    r = sig_bytes[:32]
    s = sig_bytes[32:64]
    v = sig_bytes[64]

    # Convert v from 27/28 → 0/1
    if v >= 27:
        v = v - 27

    canonical_sig = r + s + bytes([v])

    sig_obj = keys.Signature(signature_bytes=canonical_sig)
    pubkey = sig_obj.recover_public_key_from_msg_hash(message_hash)
    return pubkey.to_checksum_address()

def main():
    # Read attestation from json file
    with open('attestation.json', 'r', encoding='utf-8') as f:
        attestation_dict = json.load(f)
    # convert to object
    request = AttNetworkRequest(**attestation_dict['request'])
    reponse_resolve = [AttNetworkResponseResolve(**r) for r in attestation_dict['reponseResolve']]
    attestors = [Attestor(**a) for a in attestation_dict.get('attestors', [])]
    attestation = Attestation(
        recipient=attestation_dict['recipient'],
        request=request,
        reponseResolve=reponse_resolve,
        data=attestation_dict['data'],
        attConditions=attestation_dict['attConditions'],
        timestamp=attestation_dict['timestamp'],
        additionParams=attestation_dict['additionParams'],
        attestors=attestors,
        signatures=attestation_dict.get('signatures', [])
    )
    attestation_hash = encode_attestation(attestation)
    print("attestationEncode:", attestation_hash)
    print("attestationSignature:", attestation.signatures[0][2:])
    signer = recover_address(attestation_hash, attestation.signatures[0][2:])
    print("signer is:", signer)
    print("verify result:" ,signer.lower()=="0xDB736B13E2f522dBE18B2015d0291E4b193D8eF6".lower())

if __name__ == "__main__":
    main()