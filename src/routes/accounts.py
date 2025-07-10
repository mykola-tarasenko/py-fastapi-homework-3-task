from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from database import get_db, ActivationTokenModel, UserModel
from database.crud import create_user, get_user_by_email
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201,
)
async def register(
    user: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    try:
        db_user = await get_user_by_email(db, user.email)
        if db_user:
            raise HTTPException(
                status_code=409,
                detail=f"A user with this email {db_user.email} already exists.",
            )
        return await create_user(db, user)
    except ValueError as msg:
        raise HTTPException(
            status_code=422,
            detail=str(msg),
        )
    except SQLAlchemyError:
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation.",
        )
    finally:
        await db.rollback()


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
)
async def activate(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    db_user = await get_user_by_email(db, data.email)

    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token = await db.scalar(
        select(ActivationTokenModel).where(ActivationTokenModel.user == db_user)
    )

    if (
        not token
        or token.token != data.token
        or datetime.now(timezone.utc) > token.expires_at.replace(tzinfo=timezone.utc)
    ):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    db_user.is_active = True
    await db.delete(token)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")
