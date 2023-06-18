import os

from . import *
from .util import getenv_or_raise

if __name__ == "__main__":
    try:
        contract_path = getenv_or_raise("CONTRACT_PATH")
        contract_value = int(os.getenv("CONTRACT_DEPLOY_VALUE", "0"))
        contract_args = os.getenv("CONTRACT_DEPLOY_ARGS", "")

        run_launcher([
        new_launch_instance_action(setup(contract_path, contract_value, contract_args)),
        new_kill_instance_action(),
        new_get_flag_action()
    ])
    except Exception as e:
        print(f"Error while deploying contract: {e}")