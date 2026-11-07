"""Cut an agent off at the identity provider, not just at the gateway.

Revoking in Lanyard blocks the agent's next call. Removing its client grant in Auth0 also stops
Auth0 from issuing it any new token for the Lanyard API. Restore recreates the grant with the
same scopes. Needs a machine-to-machine app authorized for the Auth0 Management API with
read:client_grants, create:client_grants and delete:client_grants.
"""

import time

import httpx


class Auth0Admin:
    def __init__(self, domain: str, client_id: str, client_secret: str, api_audience: str,
                 http: httpx.AsyncClient):
        self._domain, self._id, self._secret = domain, client_id, client_secret
        self._api_audience, self._http = api_audience, http
        self._token, self._token_exp = None, 0.0

    async def _headers(self) -> dict:
        if not self._token or time.time() > self._token_exp - 60:
            r = await self._http.post(f"https://{self._domain}/oauth/token", json={
                "grant_type": "client_credentials", "client_id": self._id, "client_secret": self._secret,
                "audience": f"https://{self._domain}/api/v2/"})
            r.raise_for_status()
            data = r.json()
            self._token, self._token_exp = data["access_token"], time.time() + data["expires_in"]
        return {"authorization": f"Bearer {self._token}"}

    async def remove_grant(self, client_id: str) -> list[str] | None:
        """Delete the agent's grant for the Lanyard API. Returns its scopes, or None if it had none."""
        url = f"https://{self._domain}/api/v2/client-grants"
        r = await self._http.get(url, headers=await self._headers(),
                                 params={"client_id": client_id, "audience": self._api_audience})
        r.raise_for_status()
        grants = r.json()
        if not grants:
            return None
        grant = grants[0]
        d = await self._http.delete(f"{url}/{grant['id']}", headers=await self._headers())
        d.raise_for_status()
        return grant.get("scope", [])

    async def restore_grant(self, client_id: str, scopes: list[str]) -> None:
        r = await self._http.post(f"https://{self._domain}/api/v2/client-grants", headers=await self._headers(),
                                  json={"client_id": client_id, "audience": self._api_audience, "scope": scopes})
        if r.status_code != 409:  # 409: grant already exists
            r.raise_for_status()
