from typing import Type, TypeVar
from fastapi import FastAPI

from authshield.csrf._use_csrf import use_csrf
from authshield.auth._use_auth import use_auth

T = TypeVar("T", bound=FastAPI)

def shield_class(base_cls: Type[T]) -> Type[T]:
    """Dynamically creates a new class extending the provided base class

    with AuthShield capabilities.
    """
    methods_dict = {
        "use_csrf": use_csrf,
        "use_auth": use_auth,
    }

    shielded_cls = type(
        f"Shielded{base_cls.__name__}",
        (base_cls,),
        methods_dict
    )
    return shielded_cls