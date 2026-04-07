import logging
from typing import Annotated

import jwt
from fastapi import Depends, Cookie, HTTPException
from sqlmodel import select

from backend.api.dependencies.get_session import SQLSessionDep
from common.auth import parse_auth_token
from common.database.postgres_models import User
from common.settings import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)


async def get_current_user(
    session: SQLSessionDep,
    session_token: Annotated[str | None, Cookie()] = None,
) -> User:
    """
    FastAPI dependency to get the current user based on JWT passed via
    'session_token' cookie. If user doesn't exist, it will be created.

    Args:
        session_token: JWT sent from frontend in a cookie

    Returns:
        User: user object fetched or created in the database
    """

    authorization: str | None = session_token

    # Local / test JWT for development
    if settings.ENVIRONMENT in ["local", "integration-test"] and not authorization:
        jwt_dict = {
            "sub": "90429234-4031-7077-b9ba-60d1af121245",
            "aud": "account",
            "email_verified": "true",
            "preferred_username": "test@test.co.uk",
            "email": "test@test.co.uk",
            "username": "test@test.co.uk",
            "exp": 1727262399,
            "iss": "https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_example",
            "realm_access": {"roles": ["minute"]},
        }
        jwt_headers = {
            "typ": "JWT",
            "kid": "1234947a-59d3-467c-880c-f005c6941ffg",
            "alg": "HS256",
            "iss": "https://auth.dev.i.ai.gov.uk/realms/i_ai",
            "exp": 1727262399,
        }
        authorization = jwt.encode(jwt_dict, "secret", algorithm="HS256", headers=jwt_headers)

    if not authorization:
        logger.info("No session_token cookie provided")
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        # Extract email and claims
        email, claims = await parse_auth_token(authorization)

        # Try to find existing user
        statement = select(User).where(User.email == email)
        user = (await session.exec(statement)).first()

        # If user doesn't exist, create it
        if not user:
            user = User(email=email)
            session.add(user)
            await session.commit()
            await session.refresh(user)

        return user

    except Exception:
        logger.exception("Failed to decode token")
        raise HTTPException(
            status_code=401,
            detail="Failed to decode token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Dependency alias for FastAPI endpoints
UserDep = Annotated[User, Depends(get_current_user)]