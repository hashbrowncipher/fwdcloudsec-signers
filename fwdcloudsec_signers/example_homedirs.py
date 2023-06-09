import json
import uuid
import xml.etree.ElementTree as ETree
from datetime import datetime
from datetime import timedelta
from traceback import format_exc
from wsgiref.simple_server import make_server

import requests
from botocore.auth import S3SigV4Auth
from botocore.auth import SIGV4_TIMESTAMP
from botocore.awsrequest import AWSRequest
from botocore.compat import parse_qsl
from botocore.compat import urlencode
from botocore.compat import urlsplit
from botocore.compat import urlunsplit
from botocore.session import Session
from werkzeug import Request
from werkzeug import Response
from werkzeug.exceptions import BadRequest
from werkzeug.exceptions import Forbidden
from werkzeug.exceptions import HTTPException
from werkzeug.exceptions import InternalServerError
from werkzeug.exceptions import Unauthorized

from .list_api import Substitutions
from .list_api import visit
from .strings import trim_end
from .strings import trim_start

BUCKET_MAP = dict(
    permanent=("us-west-2", "permanent-quoic7ui7jhvtjt6"),
)
# Must be less than 15 minutes
# Or the signatures won't be valid upon issuance
VALIDITY = timedelta(minutes=15)
SHA256_OF_ZERO_BYTES = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)


def _parse_xml_string_to_dom(xml_string):
    # Taken from botocore parsers.py
    parser = ETree.XMLParser(target=ETree.TreeBuilder(), encoding="utf-8")
    parser.feed(xml_string)
    return parser.close()


class S3RemoteAuth(S3SigV4Auth):
    def _modify_request_before_signing(self, request):
        # The default implementation blanks X-Amz-Content-SHA256
        # and we'd prefer to keep it
        return super(S3SigV4Auth, self)._modify_request_before_signing(request)

    def _should_sha256_sign_payload(self, request):
        return False


def _get_netloc(bucket):
    try:
        region, bucket = BUCKET_MAP[bucket]
    except KeyError:
        raise Forbidden(f"Disallowed bucket {bucket}")

    return region, f"{bucket}.s3.{region}.amazonaws.com"


AMAZONAWS = ".amazonaws.com"


def _split_for_path_based_address(parts: list[str], path: str):
    parts.pop()
    if parts:
        # vhost style
        return ".".join(parts), path

    bucket, key = path.split("/", maxsplit=1)
    return bucket, key


def _get_bucket(netloc, path):
    if netloc.endswith("."):
        netloc = netloc[:-1]

    netloc = trim_end(netloc, ".amazonaws.com")
    parts = netloc.split(".")

    last_part = parts[-1]
    if last_part == "s3" or last_part.startswith("s3-"):
        # Path-based addressing
        return _split_for_path_based_address(parts, path)

    # region
    _ = parts.pop()

    if not parts:
        return None

    if parts[-1] != "s3":
        return None

    return _split_for_path_based_address(parts, path)


def _handle_list(*, request, bucket, split, headers):
    headers = dict(headers)
    headers["Authorization"] = request.headers["Authorization"]
    return dict(
        url=urlunsplit(
            ("http", "localhost:8000", "list/" + bucket, split.query, split.fragment)
        ),
        headers=headers,
    )


def _get_user(request):
    authz = request.authorization
    if not authz or not authz.username:
        raise Unauthorized("Need a username\n")

    user = authz.username

    if "/" in user:
        raise Forbidden(f"Disallowed user {user}\n")

    return user


def _transform_url(bucket, key, caller, split):
    region, netloc = _get_netloc(bucket)

    key = f"/{caller}/{key}"
    url = urlunsplit((split.scheme, netloc, key, split.query, split.fragment))
    return region, url


def _transform_headers(account, method, headers):
    headers = dict((k.lower(), v) for k, v in headers.items())
    if method != "GET":
        # Add metadata on all writes
        # This will be visible when the object is retrieved
        headers["x-amz-meta-fwdcloudsec-request-id"] = str(uuid.uuid4())
        headers["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD"
    else:
        headers["x-amz-content-sha256"] = SHA256_OF_ZERO_BYTES

    headers["x-amz-expected-bucket-owner"] = account

    return headers


class CustomTimestampContext(dict):
    def __init__(self, validity):
        # This backdates the X-Amz-Date header. The signed request is valid for 15
        # minutes from the time on the date header, so if we backdate by 14 minutes
        # then the URL we produce is only valid for 1 minute
        # You could also forward-date, if you wanted to be able to do some API request
        # for a 15 minute interval starting at some point in the future.
        now = datetime.utcnow() - timedelta(minutes=15) + validity
        super().__setitem__("timestamp", now.strftime(SIGV4_TIMESTAMP))

    def __setitem__(self, key, value):
        if key == "timestamp":
            return

        super().__setitem__(key, value)


class App:
    def __init__(self):
        self._session = Session()
        self._account = self._session.create_client("sts").get_caller_identity()[
            "Account"
        ]

    def _add_auth(self, request, region):
        credentials = self._session.get_component(
            "credential_provider"
        ).load_credentials()
        auth = S3RemoteAuth(credentials, "s3", region)
        auth.add_auth(request)

    def _handle_signing_request(self, request, user, body):
        method, url, headers = body["method"], body["url"], body["headers"]
        split = urlsplit(url)
        bucket, key = _get_bucket(split.netloc, split.path[1:])

        if key == "":
            return _handle_list(
                request=request, bucket=bucket, split=split, headers=headers
            )

        region, url = _transform_url(bucket, key, user, split)
        headers = _transform_headers(self._account, method, headers)

        # Synthesize a request and sign it.
        synthetic_request = AWSRequest(method=method, url=url, headers=headers)
        synthetic_request.context = CustomTimestampContext(VALIDITY)
        synthetic_request.context["payload_signing_enabled"] = True

        self._add_auth(synthetic_request, region)

        return dict(
            url=url,
            headers=dict(synthetic_request.headers),
        )

    def sign(self, caller, request):
        body = json.load(request.stream)
        signed = self._handle_signing_request(request, caller, body)
        response_text = json.dumps(signed)
        return Response(response_text, mimetype="application/json")

    def list(self, caller, request, bucket):
        query_kv = parse_qsl(
            request.query_string, keep_blank_values=True, strict_parsing=True
        )
        query_kv = dict(query_kv)

        if query_kv.get(b"encoding-type", b"url") != b"url":
            raise BadRequest("Unknown encoding-type")

        query_kv[b"prefix"] = caller.encode() + b"/" + query_kv.get(b"prefix")
        query = urlencode(query_kv)

        region, netloc = _get_netloc(bucket)
        url = urlunsplit(("https", netloc, "/", query, ""))

        headers = dict(request.headers)
        headers.pop("Authorization")
        headers.pop("Host")

        headers["x-amz-content-sha256"] = SHA256_OF_ZERO_BYTES
        synthetic_request = AWSRequest(method="GET", url=url, headers=headers)
        self._add_auth(synthetic_request, region)

        resp = requests.get(synthetic_request.url, headers=synthetic_request.headers)

        element = _parse_xml_string_to_dom(resp.text)
        visit(Substitutions(caller=caller, bucket=bucket), element)

        xml_str = ETree.tostring(
            element, default_namespace="http://s3.amazonaws.com/doc/2006-03-01/"
        )
        headers = dict(resp.headers)
        headers.pop("Transfer-Encoding", None)
        headers.pop("Content-Length", None)

        return Response(xml_str, headers=headers)

    @Request.application
    def __call__(self, request):
        try:
            caller = _get_user(request)

            if request.path == "/":
                return self.sign(caller, request)

            if list_bucket := trim_start(request.path, "/list/"):
                return self.list(caller, request, list_bucket)
        except HTTPException as e:
            return e
        except Exception:
            tb = format_exc()
            print(format_exc())
            return InternalServerError(tb)


def main():
    with make_server("", 8000, App()) as httpd:
        print("Serving on port 8000...")
        httpd.serve_forever()


if __name__ == "__main__":
    raise SystemExit(main())
