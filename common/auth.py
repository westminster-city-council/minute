import os, time
import logging
from typing import Annotated

import httpx
from fastapi import Depends, Cookie, HTTPException
from sqlmodel import select
from jose import jwt, jwk
from jose.utils import base64url_decode

from backend.api.dependencies.get_session import SQLSessionDep
from common.database.postgres_models import User

logger = logging.getLogger(__name__)


class AuthorisationError(Exception):
    pass


async def get_jwks_keys(jwks_uri: str) -> dict:
    """
    Fetches JWKS keys from Azure or any JWKS URI.
    """
    async with httpx.AsyncClient() as client:
        resp = await client.get(jwks_uri)
        resp.raise_for_status()
        return {key["kid"]: key for key in resp.json()["keys"]}


def verify_jwt_with_jwks(token: str, jwks_keys: dict, issuer: str, audience: str) -> dict:
    """
    Verifies a JWT using a JWKS key based on the token header kid.
    """
    headers = jwt.get_unverified_header(token)
    kid = headers.get("kid")
    if not kid or kid not in jwks_keys:
        raise AuthorisationError("Invalid token header or unknown kid")

    key_dict = jwks_keys[kid]
    # Construct JWK with algorithm explicitly
    try:
        public_key = jwk.construct(key_dict, algorithm="RS256")
    except Exception as e:
        raise AuthorisationError(f"Failed to construct JWK: {e}")

    # Verify signature
    message, encoded_signature = token.rsplit(".", 1)
    decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))
    if not public_key.verify(message.encode("utf-8"), decoded_signature):
        raise AuthorisationError("Signature verification failed")

    # Decode claims without verifying signature again
    claims = jwt.get_unverified_claims(token)

    # Validate standard claims
    if claims.get("iss") != issuer:
        raise AuthorisationError(f"Invalid issuer: {claims.get('iss')}")
    if audience not in claims.get("aud", []):
        raise AuthorisationError(f"Invalid audience: {claims.get('aud')}")
    if "exp" in claims and claims["exp"] < int(time.time()):
        raise AuthorisationError("Token expired")

    return claims


async def parse_auth_token(auth_token: str) -> tuple[str, dict]:
    """
    Parses and verifies JWT from session_token cookie using JWKS.
    Returns (email, claims)
    """
    if not auth_token:
        logger.error("No auth token provided")
        raise AuthorisationError("No auth token provided")

    jwks_uri = os.environ.get("AZURE_JWKS_URI")
    if not jwks_uri:
        raise AuthorisationError("JWKS URI not configured")

    # --- before calling verify_jwt_with_jwks ---
    tenant_id = os.environ.get("AZURE_TENANT_ID")
    if not tenant_id:
        raise AuthorisationError("AZURE_TENANT_ID environment variable is not set")
    
    issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
    
    audience = os.environ.get("AZURE_CLIENT_ID")
    if not audience:
        raise AuthorisationError("AZURE_CLIENT_ID environment variable is not set")

    jwks_keys = await get_jwks_keys(jwks_uri)
    claims = verify_jwt_with_jwks(auth_token, jwks_keys, issuer, audience)

    email = claims.get("email")
    if not email:
        raise AuthorisationError("No email found in token")

    return email, claims


async def get_current_user(
    session: SQLSessionDep,
    session_token: Annotated[str | None, Cookie()] = None,
) -> User:
    """
    FastAPI dependency: reads JWT from cookie, decodes and verifies it using JWKS,
    and fetches or creates the user.
    """
    if not session_token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        email, claims = await parse_auth_token(session_token)

        # Lookup existing user
        statement = select(User).where(User.email == email)
        user = (await session.exec(statement)).first()

        # Create user if doesn't exist
        if not user:
            user = User(email=email)
            session.add(user)
            await session.commit()
            await session.refresh(user)

        return user

    except AuthorisationError as e:
        logger.exception("JWT auth failed")
        raise HTTPException(status_code=401, detail=str(e))


# Alias for FastAPI endpoint injection
UserDep = Annotated[User, Depends(get_current_user)]