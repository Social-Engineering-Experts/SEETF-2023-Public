import os
import sys
from typing import Optional

def getenv_or_raise(key: str) -> Optional[str]:
    """
    Gets the value of an environment variable.
    Raises an EnvironmentError if the variable is not set.
    """
    try:
        value = os.getenv(key)
        if value is None:
            raise EnvironmentError(f"No {key} set!")
        return value
    except Exception as e:
        print(f"Error while retrieving environment variable: {e}")
        sys.exit(1)
