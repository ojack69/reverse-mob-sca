import random
import string

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REQUEST_TIMEOUT = 30


def make_session(proxy: str = None):
    """Shared session; a proxy (for interception/debugging) disables TLS verification."""
    session = requests.Session()
    session.headers["User-Agent"] = (
        f"python-{''.join(random.choices(string.ascii_letters + string.digits, k=8))}"
    )
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
        session.verify = False
    return session
