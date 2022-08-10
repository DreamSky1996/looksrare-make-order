from web3 import Web3, HTTPProvider
from eth_account.messages import encode_structured_data
import json
from time import time
from constants import addressesByNetwork, SupportedChainId
from eth_abi import encode_abi
import requests

TEST_FLAG = False
API_Key = ""

rpc_url = "https://mainnet.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161"
if TEST_FLAG:
    rpc_url = "https://rinkeby.infura.io/v3/9aa3d95b3bc440fa88ea12eaa4456161"

def getNonce(address):
    url ="https://api.looksrare.org/api/v1/orders/nonce?address=" + address
    if TEST_FLAG:
        url ="https://api-rinkeby.looksrare.org/api/v1/orders/nonce?address=" + address
    res = requests.get(url)
    info = res.json()
    return info['data']

def getDomainAndType(chainId, verifyingContract=None):
    verifyingContract_domain = verifyingContract
    if verifyingContract == None:
        verifyingContract_domain = addressesByNetwork[chainId]["EXCHANGE"]
    domain = {
        "name": "LooksRareExchange",
        "version": "1",
        "chainId": chainId,
        "verifyingContract": verifyingContract_domain,
    }
    return domain

def signMakerOrder (privateKey, chainId, order, verifyingContractAddress=None):
    domain = getDomainAndType(chainId, verifyingContractAddress)
    msg = {
        'domain': domain,
        'message': order,
        'primaryType': "MakerOrder",
        'types': {
            "EIP712Domain": [
                { 'name': 'name', 'type': 'string' },
                { 'name': 'version', 'type': 'string' },
                { 'name': 'chainId', 'type': 'uint256' },
                { 'name': 'verifyingContract', 'type': 'address' },
            ],
            "MakerOrder": [
                { "name": "isOrderAsk", "type": "bool" },
                { "name": "signer", "type": "address" },
                { "name": "collection", "type": "address" },
                { "name": "price", "type": "uint256" },
                { "name": "tokenId", "type": "uint256" },
                { "name": "amount", "type": "uint256" },
                { "name": "strategy", "type": "address" },
                { "name": "currency", "type": "address" },
                { "name": "nonce", "type": "uint256" },
                { "name": "startTime", "type": "uint256" },
                { "name": "endTime", "type": "uint256" },
                { "name": "minPercentageToAsk", "type": "uint256" },
                { "name": "params", "type": "address[]" },
            ],
        }
    }
    msg_dump = json.dumps(msg)
    msg_lods = json.loads(msg_dump)
    msg_lods['types']['MakerOrder'][12]['type'] = "bytes"
    msg_lods['message']['params'] = encode_abi([], order["params"])
    encoded_msg = encode_structured_data(msg_lods)
    w3 = Web3(HTTPProvider(rpc_url))
    signed_msg = w3.eth.account.sign_message(encoded_msg, privateKey)
    return signed_msg

if __name__ == '__main__':
    privateKey = "0xd250e91b58d892974c3fb69101408db7edfafb396abd7a640ecddf79b5106dfb"
    signer_address = "0x10A073241427Bf63DBbddee4da2f5eCFa8C91Bd0"
    collection_address = "0xe14025a1fd3cf44b112175281c56c20170af5650"
    if TEST_FLAG:
        collection_address = "0x98b54f7e8BA01901e6Ac4E40149b3689acCE1b43"
    now = int(time())
    paramsValue = []
    chainId = SupportedChainId["MAINNET"]
    if TEST_FLAG:
        chainId = SupportedChainId["RINKEBY"]
    addresses = addressesByNetwork[chainId]
    nonce = int(getNonce(signer_address))

    makerOrder = {
        "isOrderAsk": True,
        "signer": signer_address,
        "collection": collection_address,
        "price": 100000000000000000,
        "tokenId": 1,
        "amount": 1,
        "strategy": addresses["STRATEGY_STANDARD_SALE"],
        "currency": addresses["WETH"],
        "nonce": nonce,
        "startTime": now,
        "endTime": now + 86375,
        "minPercentageToAsk": 9800,
        "params": paramsValue,
    }
    
    signatureHash = signMakerOrder(privateKey, chainId, makerOrder)
    signatureStr = signatureHash.signature.hex()
    order_body = {
        "signature": signatureStr,
        "isOrderAsk": True,
        "signer": signer_address,
        "collection": collection_address,
        "price": "100000000000000000",
        "tokenId": "1",
        "amount": 1,
        "strategy": addresses["STRATEGY_STANDARD_SALE"],
        "currency": addresses["WETH"],
        "nonce": nonce,
        "startTime": now,
        "endTime": now + 86375,
        "minPercentageToAsk": 9800,
        "params": paramsValue,
    }
    Headers = { "X-Looks-Api-Key" : API_Key }
    url = "https://api.looksrare.org/api/v1/orders"
    if TEST_FLAG:
        url = "https://api-rinkeby.looksrare.org/api/v1/orders"
    order_res = requests.post(url, json = order_body, headers = Headers)
    print(order_res.text)