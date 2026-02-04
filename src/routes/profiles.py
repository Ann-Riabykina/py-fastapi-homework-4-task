import os

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager, get_s3_storage_client
from database import get_db, UserModel, UserProfileModel, UserGroupEnum
from database.models.accounts import GenderEnum
from exceptions import BaseSecurityError, S3FileUploadError
from schemas.profiles import ProfileCreateSchema, ProfileResponseSchema
from security.interfaces import JWTAuthManagerInterface
from storages import S3StorageInterface

router = APIRouter()


def get_token(request: Request) -> str:
    authorization: str | None = request.headers.get("Authorization")

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header is missing"
        )

    scheme, _, token = authorization.partition(" ")

    if scheme.lower() != "bearer" or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Expected 'Bearer <token>'"
        )

    return token


async def get_profile_payload(request: Request) -> ProfileCreateSchema:
    form = await request.form()
    try:
        return ProfileCreateSchema(
            first_name=form.get("first_name"),
            last_name=form.get("last_name"),
            gender=form.get("gender"),
            date_of_birth=form.get("date_of_birth"),
            info=form.get("info"),
            avatar=form.get("avatar"),
        )
    except ValidationError as e:
        raise RequestValidationError(e.errors())


@router.post(
    "/users/{user_id}/profile/",
    response_model=ProfileResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def create_user_profile(
    user_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    s3_client: S3StorageInterface = Depends(get_s3_storage_client),
) -> ProfileResponseSchema:
    token = get_token(request)

    try:
        token_data = jwt_manager.decode_access_token(token)
    except BaseSecurityError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    current_user_id = token_data.get("user_id")

    payload = await get_profile_payload(request)

    stmt_current = (
        select(UserModel)
        .options(joinedload(UserModel.group))
        .where(UserModel.id == current_user_id)
    )
    res_current = await db.execute(stmt_current)
    current_user = res_current.scalars().first()

    if current_user is None or not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or not active.",
        )

    is_admin = current_user.group is not None and current_user.group.name == UserGroupEnum.ADMIN
    if (current_user.id != user_id) and (not is_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to edit this profile.",
        )

    stmt_target = select(UserModel).where(UserModel.id == user_id)
    res_target = await db.execute(stmt_target)
    target_user = res_target.scalars().first()

    if target_user is None or not target_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or not active.",
        )

    stmt_profile = select(UserProfileModel).where(UserProfileModel.user_id == user_id)
    res_profile = await db.execute(stmt_profile)
    if res_profile.scalars().first() is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already has a profile.",
        )

    filename = payload.avatar.filename
    _, ext = os.path.splitext(filename)
    ext = ext.lower()

    avatar_key = f"avatars/{user_id}_avatar.{ext}"
    avatar_bytes = await payload.avatar.read()

    try:
        await s3_client.upload_file(avatar_key, avatar_bytes)
    except S3FileUploadError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to upload avatar. Please try again later.",
        )

    profile = UserProfileModel(
        user_id=user_id,
        first_name=payload.first_name.lower(),
        last_name=payload.last_name.lower(),
        gender=GenderEnum(payload.gender),
        date_of_birth=payload.date_of_birth,
        info=payload.info,
        avatar=avatar_key,
    )

    db.add(profile)
    await db.commit()
    await db.refresh(profile)

    avatar_url = await s3_client.get_file_url(avatar_key)

    return ProfileResponseSchema(
        id=profile.id,
        user_id=profile.user_id,
        first_name=profile.first_name,
        last_name=profile.last_name,
        gender=profile.gender.value,
        date_of_birth=profile.date_of_birth,
        info=profile.info,
        avatar=avatar_url,
    )
