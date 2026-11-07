"""Signing and verifying the tokens Lanyard issues itself (workload identities, sub-agents).

With LANYARD_KMS_KEY_ID set, tokens are RS256 and signed by an AWS KMS key: the private key
never leaves KMS, Lanyard never holds it, and anyone can verify tokens with the public key
published at /.well-known/jwks.json. Without KMS (local development) tokens fall back to HS256
with LANYARD_SIGNING_KEY. Each mode accepts only its own algorithm.
"""

import base64
import hashlib
import json

import jwt
from cryptography.hazmat.primitives.serialization import load_der_public_key


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class TokenSigner:
    def __init__(self, kms_key_id: str | None, hmac_key: str | None, profile: str | None, region: str):
        self.kms_key_id, self.hmac_key = kms_key_id, hmac_key
        self._kms, self._public_key, self.kid = None, None, None
        if kms_key_id:
            import boto3
            self._kms = boto3.Session(profile_name=profile, region_name=region).client("kms")

    @property
    def enabled(self) -> bool:
        return bool(self.kms_key_id or self.hmac_key)

    @property
    def algorithm(self) -> str:
        return "RS256" if self.kms_key_id else "HS256"

    def _load_public_key(self):
        if self._public_key is None:
            r = self._kms.get_public_key(KeyId=self.kms_key_id)
            self._public_key = load_der_public_key(r["PublicKey"])
            self.kid = r["KeyId"].rsplit("/", 1)[-1]
        return self._public_key

    def sign(self, claims: dict) -> str:
        if not self.kms_key_id:
            return jwt.encode(claims, self.hmac_key, algorithm="HS256")
        self._load_public_key()
        header = {"alg": "RS256", "typ": "JWT", "kid": self.kid}
        signing_input = f"{_b64(json.dumps(header, separators=(',', ':')).encode())}." \
                        f"{_b64(json.dumps(claims, separators=(',', ':')).encode())}"
        signature = self._kms.sign(KeyId=self.kms_key_id, Message=hashlib.sha256(signing_input.encode()).digest(),
                                   MessageType="DIGEST", SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256")["Signature"]
        return f"{signing_input}.{_b64(signature)}"

    def verify(self, token: str, audience: str, issuer: str) -> dict:
        if self.kms_key_id:
            return jwt.decode(token, self._load_public_key(), algorithms=["RS256"], audience=audience, issuer=issuer)
        return jwt.decode(token, self.hmac_key, algorithms=["HS256"], audience=audience, issuer=issuer)

    def jwks(self) -> dict:
        if not self.kms_key_id:
            return {"keys": []}  # HMAC keys are secret; nothing to publish
        numbers = self._load_public_key().public_numbers()
        to_b64 = lambda n: _b64(n.to_bytes((n.bit_length() + 7) // 8, "big"))  # noqa: E731
        return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid,
                          "n": to_b64(numbers.n), "e": to_b64(numbers.e)}]}
