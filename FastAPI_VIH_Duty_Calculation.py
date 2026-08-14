import base64
import logging
import os
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vih_duty_calculation")

app = FastAPI()

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


def build_duty_update_xml(shipment_number: str, total_duty: float) -> str:
    return (
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
        f"<SubShipmentCollection>"
        f"<SubShipment>"
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
        f"</SubShipment>"
        f"</SubShipmentCollection>"
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
    resp.raise_for_status()
    return resp


@app.get("/")
def health_check():
    return {"status": "ok"}


@app.post("/cw/duty_calculation")
async def receive_xml(request: Request):
    body = await request.body()
    xml_data = body.decode("utf-8")

    os.makedirs("xml_logs", exist_ok=True)
    xml_filename = f"xml_logs/cw_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.xml"
    with open(xml_filename, "w", encoding="utf-8") as f:
        f.write(xml_data)

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as exc:
        logger.exception("Failed to parse inbound XML")
        raise HTTPException(status_code=400, detail=f"Invalid XML: {exc}") from exc

    try:
        shipment_number, total_duty = calculate_total_duty(root)
    except ValueError as exc:
        logger.exception("Failed to extract duty data")
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    logger.info("Shipment %s total duty %.2f", shipment_number, total_duty)

    update_xml = build_duty_update_xml(shipment_number, total_duty)

    try:
        push_to_cargowise(update_xml)
    except requests.RequestException as exc:
        logger.exception("Failed to push duty update to CargoWise")
        raise HTTPException(status_code=502, detail=f"CargoWise push failed: {exc}") from exc

    logger.info("Duty amount %.2f pushed to CargoWise for shipment %s", total_duty, shipment_number)
    return PlainTextResponse("OK")
