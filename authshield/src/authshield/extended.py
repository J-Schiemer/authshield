from typing import Type, TypeVar
from fastapi import FastAPI

T = TypeVar("T", bound=FastAPI)

def shield_class(base_cls: Type[T]) -> Type[T]:
    """Dynamically creates a new class extending the provided base class

    with AuthShield capabilities.
    """
    # Define attached methods
    methods_dict = {
    # e.g.    "useOAuth": useOAuth,
    # e.g.    "useAuth": useAuth,
    }

    # Create a brand new class on the fly combining the base and the methods
    shielded_cls = type(
        f"Shielded{base_cls.__name__}", 
        (base_cls,), 
        methods_dict
    )
    return shielded_cls