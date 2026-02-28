"""Sample app that imports some packages."""

import requests
from yaml import safe_load


def fetch_config(url):
    resp = requests.get(url)
    return safe_load(resp.text)
