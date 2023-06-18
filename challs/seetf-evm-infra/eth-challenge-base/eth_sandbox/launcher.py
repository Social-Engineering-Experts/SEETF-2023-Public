import json
import os
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from uuid import UUID
from pathlib import Path

import requests
from eth_account import Account
from web3 import Web3
from web3.exceptions import TransactionNotFound
from web3.types import TxReceipt

from eth_abi import encode_abi

from eth_sandbox import get_shared_secret
from .util import getenv_or_raise

HTTP_PORT = os.getenv("HTTP_PORT", "8545")
PUBLIC_IP = os.getenv("PUBLIC_IP", "127.0.0.1")
PLAYER_VALUE = int(os.getenv("PLAYER_VALUE", "0"))

FLAG = getenv_or_raise("FLAG")

Account.enable_unaudited_hdwallet_features()


@dataclass
class Action:
    name: str
    handler: Callable[[], int]


def sendTransaction(web3: Web3, tx: Dict) -> Optional[TxReceipt]:
    if "gas" not in tx:
        tx["gas"] = 10_000_000

    if "gasPrice" not in tx:
        tx["gasPrice"] = 0

    txhash = web3.eth.sendTransaction(tx)

    while True:
        try:
            rcpt = web3.eth.getTransactionReceipt(txhash)
            break
        except TransactionNotFound:
            time.sleep(0.1)

    if rcpt.status != 1:
        raise Exception("failed to send transaction")

    return rcpt


def check_uuid(uuid) -> bool:
    try:
        UUID(uuid)
        return uuid
    except (TypeError, ValueError):
        return None

def prepare_and_encode_args(arg_types, arg_values):
    prepared_args = []

    for arg_type, arg_value in zip(arg_types, arg_values):
        if arg_type == 'bytes32':
            # If the argument is bytes32, convert the hexadecimal string to bytes
            prepared_arg = bytes.fromhex(arg_value[2:])  # Strip the '0x' prefix before converting
        else:
            # For all other argument types, use the value as it is
            prepared_arg = arg_value

        prepared_args.append(prepared_arg)

    # Encode all arguments together
    encoded_args = encode_abi(arg_types, prepared_args)

    return encoded_args

def setup(contract_path: str, value: int = 0, args_str: str = '') -> Callable[[Web3, str, str], str]:
    # Convert the args string into a list of arguments
    args = args_str.split(',')

    contract_data = json.loads(Path(contract_path).read_text())
    contract_abi = contract_data["abi"]

    encoded_args = b''
    
    if len(args) != 0 and args[0] != '':
        # Get the inputs type
        inputs = [input['type'] for item in contract_abi if item['type'] == 'constructor' for input in item['inputs']]

        # Prepare and encode the arguments
        encoded_args = prepare_and_encode_args(inputs, args)

    def action(web3: Web3, deployer_address: str, _: str) -> str:
        rcpt = sendTransaction(web3, {
            "from": deployer_address,
            "value": Web3.toWei(value, 'ether'),
            "data": json.loads(Path(contract_path).read_text())["bytecode"]["object"] + encoded_args.hex(),
        })
        return rcpt.contractAddress
    return action


def new_launch_instance_action(
    do_deploy: Callable[[Web3, str], str],
):
    def action() -> int:
        data = requests.post(
            f"http://127.0.0.1:{HTTP_PORT}/new",
            headers={
                "Authorization": f"Bearer {get_shared_secret()}",
                "Content-Type": "application/json",
            },
        ).json()

        if data["ok"] == False:
            print(data["message"])
            return 1

        uuid = data["uuid"]
        mnemonic = data["mnemonic"]

        deployer_acct = Account.from_mnemonic(
            mnemonic, account_path=f"m/44'/60'/0'/0/0")
        player_acct = Account.from_mnemonic(
            mnemonic, account_path=f"m/44'/60'/0'/0/1")

        web3 = Web3(Web3.HTTPProvider(
            f"http://127.0.0.1:{HTTP_PORT}/{uuid}",
            request_kwargs={
                "headers": {
                    "Authorization": f"Bearer {get_shared_secret()}",
                    "Content-Type": "application/json",
                },
            },
        ))

        player_balance = web3.eth.getBalance(player_acct.address)

        if (player_balance > web3.toWei(PLAYER_VALUE, "ether")):
            value_to_send = player_balance - web3.toWei(PLAYER_VALUE, 'ether')  # Calculating amount to send to leave 30 Ether

            # Creating a raw transaction
            raw_transaction = {
                'nonce': web3.eth.getTransactionCount(player_acct.address),
                'gasPrice': 0,
                'gas': 21000,  # gas limit - 21000 is the intrinsic gas for transaction
                'to': deployer_acct.address,
                'value': value_to_send,
            }

            # Estimating gas for the transaction
            # raw_transaction['gas'] = web3.eth.estimateGas(raw_transaction)

             # Signing the transaction
            signed_transaction = web3.eth.account.signTransaction(raw_transaction, player_acct.privateKey)

             # Sending the transaction
            tx_hash = web3.eth.sendRawTransaction(signed_transaction.rawTransaction)

            # Waiting for transaction to be mined
            receipt = web3.eth.waitForTransactionReceipt(tx_hash)

            # print(f'Transaction successful, hash: {tx_hash.hex()}, transaction cost: {receipt["gasUsed"] * raw_transaction["gasPrice"]}')

        setup_addr = do_deploy(
            web3, deployer_acct.address, player_acct.address)

        with open(f"/tmp/{uuid}", "w") as f:
            f.write(
                json.dumps(
                    {
                        "uuid": uuid,
                        "mnemonic": mnemonic,
                        "address": setup_addr,
                        "public_key": player_acct.address,
                    }
                )
            )

        port_for_display = "" if HTTP_PORT == "80" else ":" + HTTP_PORT
        print()
        print(f"your private blockchain has been deployed!")
        print(f"it will automatically terminate in 1 hour")
        print(f"here's some useful information")
        print()
        print(f"uuid:           {uuid}")
        print(f"rpc endpoint:   http://{PUBLIC_IP}{port_for_display}/{uuid}")
        print(f"private key:    {player_acct.privateKey.hex()}")
        print(f"public key:    {player_acct.address}")
        print(f"setup contract: {setup_addr}")
        return 0

    return Action(name="launch new instance", handler=action)


def new_kill_instance_action():
    def action() -> int:
        try:
            uuid = check_uuid(input("uuid please: "))
            if not uuid:
                print("invalid uuid!")
                return 1
        except Exception as e:
            print(f"Error with UUID: {e}")
            return 1

        data = requests.post(
            f"http://127.0.0.1:{HTTP_PORT}/kill",
            headers={
                "Authorization": f"Bearer {get_shared_secret()}",
                "Content-Type": "application/json",
            },
            data=json.dumps(
                {
                    "uuid": uuid,
                }
            ),
        ).json()

        print(data["message"])
        return 1

    return Action(name="kill instance", handler=action)


def is_solved_checker(web3: Web3, from_addr: str, to_addr: str) -> bool:
    result = web3.eth.call(
        {
            "from": from_addr,
            "to": to_addr,
            "data": web3.sha3(text="isSolved()")[:4],
        }
    )
    return int(result.hex(), 16) == 1



def new_get_flag_action(
    checker: Callable[[Web3, str], bool] = is_solved_checker,
):
    def action() -> int:
        try:
            uuid = check_uuid(input("uuid please: "))
            if not uuid:
                print("invalid uuid!")
                return 1
        except Exception as e:
            print(f"Error with UUID: {e}")
            return 1

        try:
            with open(f"/tmp/{uuid}", "r") as f:
                data = json.loads(f.read())
        except:
            print("bad uuid")
            return 1

        web3 = Web3(Web3.HTTPProvider(
            f"http://127.0.0.1:{HTTP_PORT}/{data['uuid']}"))

        if not checker(web3, data['public_key'], data['address']):
            print("are you *really* sure you solved it?")
            return 1

        print("\nCongratulations! You have solve it! Here's the flag: ")
        print(FLAG)
        return 0

    return Action(name="acquire flag", handler=action)


def run_launcher(actions: List[Action]):
    for i, action in enumerate(actions):
        print(f"{i+1} - {action.name}")

    action = None
    try:
        action = int(input("action? ")) - 1
        if action < 0 or action >= len(actions):
            raise
    except:
        print("that's not a valid action")
        exit(1)

    exit(actions[action].handler())
