import os

import requests
from botocore.auth import AUTH_TYPE_MAPS
from botocore.auth import BaseSigner
from requests.auth import HTTPBasicAuth


def make_signing_request(request):
    basic = HTTPBasicAuth(os.environ["USER"], "password")
    resp = requests.post("http://localhost:8000", json=request, auth=basic)
    return resp.json()


class ExternalSigner(BaseSigner):
    REQUIRES_REGION = False

    def __init__(self, credentials):
        pass

    def add_auth(self, request):
        ea_request = dict(
            method=request.method,
            url=request.url,
            params=request.params,
            headers=dict(request.headers),
        )

        response = make_signing_request(ea_request)
        request.url = response["url"]
        request.headers = response["headers"]


def choose_signer(*args, **kwargs):
    return "mysigner"


def awscli_initialize(event_hooks):
    if os.environ.get("AWS_SKIP_SIGNER", "0") != "0":
        return

    AUTH_TYPE_MAPS["mysigner"] = ExternalSigner
    event_hooks.register("choose-signer.s3", choose_signer)
