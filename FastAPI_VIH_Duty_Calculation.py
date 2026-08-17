import base64
import logging
import os
import secrets
import time
import uuid
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager
from decimal import Decimal, InvalidOperation

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import PlainTextResponse

import db_logging
from db_logging import LogEvent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vih_duty_calculation")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Starts the background Azure SQL writer thread. If the database is
    # unreachable or misconfigured this logs and disables itself - the duty
    # calculation service still starts and serves traffic.
    db_logging.start()
    yield
    db_logging.stop()


app = FastAPI(lifespan=lifespan)

CW_NAMESPACE = "http://www.cargowise.com/Schemas/Universal/2011/11"
NS = {"cw": CW_NAMESPACE}
DUTY_CHARGE_CODE = "DTY"
DUTY_FIELD_KEY = "Duty Amount"

# Azure AD (eAdaptor NEXT) app registration details.
CW_TENANT_ID = os.environ["CW_TENANT_ID"]
CW_CLIENT_ID = os.environ["CW_CLIENT_ID"]
CW_SCOPE = os.environ["CW_SCOPE"]
CW_TOKEN_URL = f"https://login.microsoftonline.com/{CW_TENANT_ID}/oauth2/v2.0/token"

# Render "Secret Files" are mounted under /etc/secrets/<filename> by default.
CW_CERT_PATH = os.environ.get("CW_CERT_PATH", "/etc/secrets/cargowise.pem")
CW_KEY_PATH = os.environ.get("CW_KEY_PATH", "/etc/secrets/cargowise.key")
CW_KEY_PASSPHRASE = os.environ.get("CW_KEY_PASSPHRASE")

_eadaptor_url = os.environ["CW_EADAPTOR_URL"]
CW_EADAPTOR_URL = _eadaptor_url if _eadaptor_url.startswith("http") else f"https://{_eadaptor_url}"

_token_cache = {"access_token": None, "expires_at": 0.0}


def _build_client_assertion() -> str:
    with open(CW_CERT_PATH, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    # x5t is the base64url SHA-1 thumbprint of the cert, used by Azure AD to
    # locate the public key matching the private key we sign the assertion with.
    x5t = base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA1())).rstrip(b"=").decode()

    with open(CW_KEY_PATH, "rb") as f:
        private_key = load_pem_private_key(
            f.read(),
            password=CW_KEY_PASSPHRASE.encode() if CW_KEY_PASSPHRASE else None,
        )

    now = int(time.time())
    payload = {
        "aud": CW_TOKEN_URL,
        "iss": CW_CLIENT_ID,
        "sub": CW_CLIENT_ID,
        "jti": str(uuid.uuid4()),
        "nbf": now,
        "exp": now + 300,
    }
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"x5t": x5t})


def get_cw_access_token() -> str:
    if _token_cache["access_token"] and _token_cache["expires_at"] > time.time() + 60:
        return _token_cache["access_token"]

    resp = requests.post(
        CW_TOKEN_URL,
        data={
            "client_id": CW_CLIENT_ID,
            "scope": CW_SCOPE,
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": _build_client_assertion(),
        },
        timeout=30,
    )
    resp.raise_for_status()
    token_data = resp.json()

    _token_cache["access_token"] = token_data["access_token"]
    _token_cache["expires_at"] = time.time() + token_data.get("expires_in", 3600)
    return _token_cache["access_token"]


def calculate_total_duty(root: ET.Element) -> tuple[str, float]:
    shipment_key_el = root.find(".//cw:DataSource[cw:Type='ForwardingShipment']/cw:Key", NS)
    if shipment_key_el is None or not shipment_key_el.text:
        raise ValueError("ForwardingShipment key not found in payload")
    shipment_number = shipment_key_el.text

    total_duty = 0.0
    for entry_line in root.findall(".//cw:EntryLine", NS):
        for charge in entry_line.findall(".//cw:EntryLineCharge", NS):
            code_el = charge.find("cw:Type/cw:Code", NS)
            if code_el is None or code_el.text != DUTY_CHARGE_CODE:
                continue
            amount_el = charge.find("cw:Amount", NS)
            if amount_el is None or not amount_el.text:
                continue
            total_duty += float(amount_el.text)

    return shipment_number, total_duty


def count_duty_lines(root: ET.Element) -> int:
    """How many EntryLineCharge elements contributed to the duty total.

    Logging only - does not affect the calculated amount.
    """
    count = 0
    for entry_line in root.findall(".//cw:EntryLine", NS):
        for charge in entry_line.findall(".//cw:EntryLineCharge", NS):
            code_el = charge.find("cw:Type/cw:Code", NS)
            amount_el = charge.find("cw:Amount", NS)
            if code_el is not None and code_el.text == DUTY_CHARGE_CODE \
                    and amount_el is not None and amount_el.text:
                count += 1
    return count


def extract_context(root: ET.Element) -> dict:
    """Best-effort pull of CargoWise DataContext identifiers for the log row.

    Every field is optional; a missing element yields None rather than an error,
    so a payload shape we have not seen before still gets logged.
    """
    def text_of(path: str):
        el = root.find(path, NS)
        return el.text.strip() if el is not None and el.text else None

    return {
        "company_code": text_of(".//cw:DataContext/cw:Company/cw:Code"),
        "enterprise_id": text_of(".//cw:DataContext/cw:EnterpriseID"),
        "server_id": text_of(".//cw:DataContext/cw:ServerID"),
    }


def client_ip_of(request: Request) -> str | None:
    """Real caller IP. Render terminates TLS at its proxy, so prefer XFF."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


def build_duty_update_xml(shipment_number: str, total_duty: float) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<UniversalShipment xmlns="{CW_NAMESPACE}" version="1.0">'
        f"<Shipment>"
        f"<DataContext>"
        f"<DataTargetCollection>"
        f"<DataTarget>"
        f"<Type>ForwardingShipment</Type>"
        f"<Key>{shipment_number}</Key>"
        f"</DataTarget>"
        f"</DataTargetCollection>"
        f"</DataContext>"
        f"<CustomizedFieldCollection>"
        f"<CustomizedField>"
        f"<DataType>String</DataType>"
        f"<Key>{DUTY_FIELD_KEY}</Key>"
        f"<Value>{total_duty:.2f}</Value>"
        f"</CustomizedField>"
        f"</CustomizedFieldCollection>"
        f"</Shipment>"
        f"</UniversalShipment>"
    )


def push_to_cargowise(update_xml: str) -> requests.Response:
    resp = requests.post(
        CW_EADAPTOR_URL,
        data=update_xml.encode("utf-8"),
        headers={
            "Authorization": f"Bearer {get_cw_access_token()}",
            "Content-Type": "text/xml",
        },
        timeout=60,
    )
    if not resp.ok:
        logger.error("CargoWise responded %s: %s", resp.status_code, resp.text)
    resp.raise_for_status()
    return resp


def _as_decimal(value: float) -> Decimal | None:
    """Convert the calculated float to Decimal for the DECIMAL(19,4) column."""
    try:
        return Decimal(f"{value:.4f}")
    except (InvalidOperation, ValueError):
        return None


# Guards /admin/dbcheck. Leave unset and the endpoint does not exist at all.
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")


@app.get("/")
def health_check():
    return {"status": "ok", "activity_log": db_logging.health()}


@app.get("/admin/dbcheck")
async def db_check(request: Request):
    """On-demand Azure SQL diagnostic, for hosts with no shell access.

        https://<your-service>.onrender.com/admin/dbcheck?token=<ADMIN_TOKEN>

    Returns 404 rather than 401/403 when the token is absent or wrong, so the
    endpoint is not discoverable by probing. Writes one Stage='Health' row on
    success.

    Set ADMIN_TOKEN in Render to enable it, and remove the variable once you
    have finished verifying - query strings tend to end up in access logs.
    """
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=404, detail="Not Found")

    supplied = request.headers.get("x-admin-token") or request.query_params.get("token") or ""
    if not secrets.compare_digest(supplied, ADMIN_TOKEN):
        raise HTTPException(status_code=404, detail="Not Found")

    # diagnose() blocks on sockets and the driver; keep it off the event loop.
    return await run_in_threadpool(db_logging.diagnose)


@app.post("/cw/duty_calculation")
async def receive_xml(request: Request):
    correlation_id = uuid.uuid4()
    started = time.monotonic()
    client_ip = client_ip_of(request)

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    body = await request.body()
    xml_data = body.decode("utf-8")

    # Metadata-only audit: fingerprint and size, never the document itself.
    payload_sha = db_logging.sha256_of(body)
    payload_bytes = len(body)

    db_logging.log_event(LogEvent(
        correlation_id=correlation_id,
        stage="Inbound",
        status="Received",
        elapsed_ms=elapsed_ms(),
        payload_bytes=payload_bytes,
        payload_sha256=payload_sha,
        client_ip=client_ip,
    ))

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as exc:
        logger.exception("Failed to parse inbound XML")
        db_logging.log_event(LogEvent(
            correlation_id=correlation_id,
            stage="Inbound",
            status="Rejected",
            elapsed_ms=elapsed_ms(),
            payload_bytes=payload_bytes,
            payload_sha256=payload_sha,
            client_ip=client_ip,
            error_type="XMLParseError",
            error_detail=str(exc),
        ))
        raise HTTPException(status_code=400, detail=f"Invalid XML: {exc}") from exc

    context = extract_context(root)

    try:
        shipment_number, total_duty = calculate_total_duty(root)
    except ValueError as exc:
        logger.exception("Failed to extract duty data")
        db_logging.log_event(LogEvent(
            correlation_id=correlation_id,
            stage="Calc",
            status="Rejected",
            elapsed_ms=elapsed_ms(),
            payload_bytes=payload_bytes,
            payload_sha256=payload_sha,
            client_ip=client_ip,
            error_type="DutyExtractionError",
            error_detail=str(exc),
            **context,
        ))
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    logger.info("Shipment %s total duty %.2f", shipment_number, total_duty)

    db_logging.log_event(LogEvent(
        correlation_id=correlation_id,
        stage="Calc",
        status="Processed",
        elapsed_ms=elapsed_ms(),
        shipment_number=shipment_number,
        duty_amount=_as_decimal(total_duty),
        duty_line_count=count_duty_lines(root),
        client_ip=client_ip,
        **context,
    ))

    update_xml = build_duty_update_xml(shipment_number, total_duty)

    try:
        response = push_to_cargowise(update_xml)
    except requests.RequestException as exc:
        logger.exception("Failed to push duty update to CargoWise")
        status_code = exc.response.status_code if exc.response is not None else None
        db_logging.log_event(LogEvent(
            correlation_id=correlation_id,
            stage="Outbound",
            status="Failed",
            elapsed_ms=elapsed_ms(),
            shipment_number=shipment_number,
            duty_amount=_as_decimal(total_duty),
            cw_http_status=status_code,
            client_ip=client_ip,
            error_type=type(exc).__name__,
            error_detail=str(exc),
            **context,
        ))
        raise HTTPException(status_code=502, detail=f"CargoWise push failed: {exc}") from exc

    logger.info("Duty amount %.2f pushed to CargoWise for shipment %s", total_duty, shipment_number)

    db_logging.log_event(LogEvent(
        correlation_id=correlation_id,
        stage="Outbound",
        status="Pushed",
        elapsed_ms=elapsed_ms(),
        shipment_number=shipment_number,
        duty_amount=_as_decimal(total_duty),
        cw_http_status=response.status_code,
        payload_bytes=len(update_xml.encode("utf-8")),
        client_ip=client_ip,
        **context,
    ))

    return PlainTextResponse("OK")
