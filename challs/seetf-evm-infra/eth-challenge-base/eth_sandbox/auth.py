from .util import getenv_or_raise

def get_shared_secret() -> str:
    """
    Retrieves the value of the environment variable "SHARED_SECRET".
    Raises an exception if the variable is not set.
    """
    return getenv_or_raise("SHARED_SECRET")