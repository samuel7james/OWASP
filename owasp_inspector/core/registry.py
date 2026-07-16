from __future__ import annotations

from owasp_inspector.core.module import Module


class ModuleRegistry:
    """In-process registry of assessment modules.

    Modules register themselves (directly or via `register_module` as a class
    decorator) instead of the engine importing each one by name — this is
    what lets Phase 5+ add new OWASP categories without editing `core/`.
    """

    def __init__(self):
        self._modules: dict[str, type[Module]] = {}

    def register(self, module_cls: type[Module]) -> type[Module]:
        name = getattr(module_cls, "name", None) or module_cls.__name__
        if name in self._modules:
            raise ValueError(f"A module named {name!r} is already registered")
        self._modules[name] = module_cls
        return module_cls

    def get(self, name: str) -> type[Module]:
        return self._modules[name]

    def all(self) -> list[type[Module]]:
        return list(self._modules.values())

    def instantiate_all(self) -> list[Module]:
        return [cls() for cls in self._modules.values()]

    def clear(self) -> None:
        self._modules.clear()


default_registry = ModuleRegistry()


def register_module(module_cls: type[Module]) -> type[Module]:
    return default_registry.register(module_cls)
