from datetime import date

from fastapi import UploadFile
from pydantic import BaseModel, field_validator

from validation import (
    validate_name,
    validate_image,
    validate_gender,
    validate_birth_date
)


class ProfileCreateSchema(BaseModel):
    first_name: str
    last_name: str
    gender: str
    date_of_birth: date
    info: str
    avatar: UploadFile

    @field_validator("first_name")
    @classmethod
    def first_name_must_be_english(cls, v: str) -> str:
        validate_name(v)
        return v

    @field_validator("last_name")
    @classmethod
    def last_name_must_be_english(cls, v: str) -> str:
        validate_name(v)
        return v

    @field_validator("gender")
    @classmethod
    def gender_must_be_valid(cls, v: str) -> str:
        validate_gender(v)
        return v

    @field_validator("date_of_birth")
    @classmethod
    def birth_date_must_be_valid(cls, v: date) -> date:
        validate_birth_date(v)
        return v

    @field_validator("info")
    @classmethod
    def info_cannot_be_empty(cls, v: str) -> str:
        if v is None or v.strip() == "":
            raise ValueError("Info field cannot be empty or contain only spaces.")
        return v

    @field_validator("avatar")
    @classmethod
    def avatar_must_be_valid_image(cls, v: UploadFile) -> UploadFile:
        validate_image(v)
        return v


class ProfileResponseSchema(BaseModel):
    id: int
    user_id: int
    first_name: str
    last_name: str
    gender: str
    date_of_birth: date
    info: str
    avatar: str
