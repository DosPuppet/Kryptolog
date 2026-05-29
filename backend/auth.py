from eth_account.messages import encode_defunct
from eth_account import Account
from web3 import Web3
import secrets
import base64
import json
import httpx
import os
from datetime import datetime, timedelta, timezone

# --- PQC Service Config ---
PQC_SERVICE_URL = os.getenv("PQC_SERVICE_URL", "http://127.0.0.1:3002")
_SERVER_PUBLIC_KEY = None

def get_server_public_key():
    global _SERVER_PUBLIC_KEY
    if _SERVER_PUBLIC_KEY:
        return _SERVER_PUBLIC_KEY
    try:
        secret = os.getenv("PQC_SHARED_SECRET")
        headers = {"x-api-key": secret} if secret else {}
        res = httpx.get(f"{PQC_SERVICE_URL}/server-public-key", headers=headers, timeout=2)
        if res.status_code == 200:
            _SERVER_PUBLIC_KEY = res.json().get("publicKey")
            return _SERVER_PUBLIC_KEY
    except Exception as e:
        print(f"Error fetching server public key: {e}")
    return None

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def b64url_decode(data: str) -> bytes:
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)

def generate_nonce():
    return secrets.token_hex(16)

def verify_pqc_signature(public_key: str, nonce: str, signature: str) -> bool:
    try:
        message_text = f"Sign in to Secure Log App with nonce: {nonce}"
        try:
            response = httpx.post(
                f"{PQC_SERVICE_URL}/verify",
                json={
                    "message": message_text,
                    "signature": signature,
                    "publicKey": public_key
                },
                headers={"x-api-key": os.getenv("PQC_SHARED_SECRET")},
                timeout=5
            )
            
            if response.status_code != 200:
                print(f"ERROR: PQC Service HTTP Error: {response.text}")
                return False
                
            result = response.json()
            return result.get("valid", False)
            
        except httpx.ConnectError:
            print("CRITICAL ERROR: PQC Service Unavailable. Is 'node backend/pqc_service.js' running?")
            return False
            
    except Exception as e:
        print(f"PQC verification error: {e}")
        return False

def verify_signature(address: str, nonce: str, signature: str) -> bool:
    if len(address) > 42:
        return verify_pqc_signature(address, nonce, signature)

    try:
        message_text = f"Sign in to Secure Log App with nonce: {nonce}"
        encoded_message = encode_defunct(text=message_text)
        recovered_address = Account.recover_message(encoded_message, signature=signature)
        return recovered_address.lower() == address.lower()
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    
    to_encode.update({"exp": expire.timestamp()})

    header = {"alg": "DILITHIUM2", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header).encode('utf-8'))
    payload_b64 = b64url_encode(json.dumps(to_encode).encode('utf-8'))
    message = f"{header_b64}.{payload_b64}"

    try:
        secret = os.getenv("PQC_SHARED_SECRET")
        headers = {"x-api-key": secret}
        res = httpx.post(f"{PQC_SERVICE_URL}/sign", json={"message": message}, headers=headers, timeout=5)
        if res.status_code != 200:
            raise Exception(f"Signing failed: {res.text}")

        signature_hex = res.json()["signature"]
        signature_bytes = bytes.fromhex(signature_hex)
        signature_b64 = b64url_encode(signature_bytes)

        return f"{message}.{signature_b64}"
    except Exception as e:
        print(f"Token creation failed: {e}")
        return None

def decode_access_token(token: str):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
            
        header_b64, payload_b64, signature_b64 = parts
        message = f"{header_b64}.{payload_b64}"

        signature_bytes = b64url_decode(signature_b64)
        signature_hex = signature_bytes.hex()

        server_key = get_server_public_key()
        if not server_key:
            return None

        res = httpx.post(
            f"{PQC_SERVICE_URL}/verify",
            json={
                "message": message,
                "signature": signature_hex,
                "publicKey": server_key
            },
            headers={"x-api-key": os.getenv("PQC_SHARED_SECRET")},
            timeout=2
        )

        valid = False
        if res.status_code == 200:
            valid = res.json().get("valid", False)

        if not valid:
            return None

        payload_json = b64url_decode(payload_b64).decode('utf-8')
        payload = json.loads(payload_json)

        exp = payload.get("exp")
        if exp:
            if datetime.now(timezone.utc).timestamp() > exp:
                return None

        return payload
        
    except Exception as e:
        print(f"Token decode error: {e}")
        return None
