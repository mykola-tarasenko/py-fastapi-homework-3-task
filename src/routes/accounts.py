from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from database.crud import create_user, get_user_by_email
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
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
