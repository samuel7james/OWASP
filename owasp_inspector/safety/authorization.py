import os

from owasp_inspector.core.exceptions import AuthorizationError

ENV_FLAG = "OWASP_INSPECTOR_AUTHORIZED"


def is_pre_authorized() -> bool:
    return os.getenv(ENV_FLAG, "").strip().lower() in {"1", "true", "yes"}


def confirm_authorization(target_url: str, *, interactive: bool = True) -> bool:
    """Require explicit confirmation that the caller is authorized to test `target_url`.

    Returns True once authorized. Raises AuthorizationError otherwise — including
    when running non-interactively without the env-var escape hatch set, since
    silently proceeding without confirmation defeats the point of the gate.
    """
    if is_pre_authorized():
        return True

    if not interactive:
        raise AuthorizationError(
            f"No authorization confirmation for {target_url!r}. "
            f"Set {ENV_FLAG}=1 to run non-interactively (CI/automation), "
            "or run interactively to confirm via prompt."
        )

    print("\n" + "=" * 60)
    print("  AUTHORIZATION REQUIRED")
    print("=" * 60)
    print(f"  Target: {target_url}")
    print("  Only scan systems you own or are explicitly authorized to test.")
    print("  Unauthorized scanning of third-party systems may be illegal.")
    answer = input("  Do you have authorization to test this target? [y/N]: ").strip().lower()
    if answer in {"y", "yes"}:
        return True
    raise AuthorizationError(f"Authorization not confirmed for {target_url!r}; scan aborted.")
