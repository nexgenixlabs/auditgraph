#!/usr/bin/env python3
"""
Export Phase 3 API Contract
===========================

Introspects all FastAPI routers (identities + posture) and emits a
``api_contract.json`` file listing every route's method, path, response
model fields, and their types.

Usage::

    python -m tests.export_api_contract          # writes backend/api_contract.json
    python -m tests.export_api_contract --check   # exits 1 if contract changed

The frontend CI step ``npm run check:contract`` calls this with ``--check``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, get_args, get_origin

from pydantic import BaseModel
from pydantic.fields import FieldInfo

# ---------------------------------------------------------------------------
# Importable route modules
# ---------------------------------------------------------------------------

from app.api.routes.identities import router as identities_router
from app.api.routes.posture import router as posture_router

CONTRACT_PATH = Path(__file__).resolve().parent.parent / "api_contract.json"


def _py_type_to_str(annotation: Any) -> str:
    """Convert a Python type annotation to a stable string representation."""
    if annotation is None:
        return "None"

    origin = get_origin(annotation)

    # Handle Optional
    args = get_args(annotation)
    if origin is type(None):
        return "null"

    # list[X]
    if origin is list:
        inner = args[0] if args else Any
        return f"list[{_py_type_to_str(inner)}]"

    # dict[K, V]
    if origin is dict:
        k = args[0] if args else Any
        v = args[1] if len(args) > 1 else Any
        return f"dict[{_py_type_to_str(k)}, {_py_type_to_str(v)}]"

    # Optional[X] = Union[X, None]
    import typing
    if origin is getattr(typing, "Union", None):
        non_none = [a for a in args if a is not type(None)]
        if len(non_none) == 1:
            return f"Optional[{_py_type_to_str(non_none[0])}]"
        return f"Union[{', '.join(_py_type_to_str(a) for a in args)}]"

    # Enum subclass — use the enum name
    if isinstance(annotation, type) and issubclass(annotation, __import__("enum").Enum):
        return annotation.__name__

    # BaseModel subclass
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation.__name__

    # Literal
    if origin is getattr(typing, "Literal", None):
        return f"Literal{list(args)}"

    # Built-in types
    if isinstance(annotation, type):
        return annotation.__name__

    return str(annotation)


def _model_fields(model_cls: type[BaseModel]) -> dict[str, str]:
    """Extract {field_name: type_string} from a Pydantic v2 model."""
    result = {}
    for name, field_info in model_cls.model_fields.items():
        result[name] = _py_type_to_str(field_info.annotation)
    return result


def _extract_routes(router: Any) -> list[dict[str, Any]]:
    """Extract route metadata from a FastAPI APIRouter."""
    routes = []
    for route in router.routes:
        methods = getattr(route, "methods", set())
        full_path = getattr(route, "path", "")

        # Get response model
        response_model = getattr(route, "response_model", None)
        response_fields = None
        response_model_name = None

        if response_model is not None:
            if isinstance(response_model, type) and issubclass(response_model, BaseModel):
                response_model_name = response_model.__name__
                response_fields = _model_fields(response_model)
            else:
                response_model_name = _py_type_to_str(response_model)

        for method in sorted(methods):
            routes.append({
                "method": method.upper(),
                "path": full_path,
                "response_model": response_model_name,
                "response_fields": response_fields,
            })

    return routes


def export_contract() -> dict[str, Any]:
    """Build the complete API contract dict."""
    all_routes = []
    all_routes.extend(_extract_routes(identities_router))
    all_routes.extend(_extract_routes(posture_router))

    # Sort for deterministic output
    all_routes.sort(key=lambda r: (r["path"], r["method"]))

    return {
        "version": "1.0",
        "generated_by": "export_api_contract.py",
        "routes": all_routes,
    }


def main() -> None:
    contract = export_contract()
    contract_json = json.dumps(contract, indent=2, sort_keys=False) + "\n"

    check_mode = "--check" in sys.argv

    if check_mode:
        if not CONTRACT_PATH.exists():
            print(f"FAIL: {CONTRACT_PATH} does not exist. Run without --check first.")
            sys.exit(1)

        existing = CONTRACT_PATH.read_text()
        if existing != contract_json:
            print("FAIL: API contract has drifted from api_contract.json")
            print("Run `python -m tests.export_api_contract` to update.")

            # Show diff summary
            existing_data = json.loads(existing)
            new_data = contract

            existing_routes = {(r["method"], r["path"]): r for r in existing_data.get("routes", [])}
            new_routes = {(r["method"], r["path"]): r for r in new_data.get("routes", [])}

            added = set(new_routes) - set(existing_routes)
            removed = set(existing_routes) - set(new_routes)

            for key in added:
                print(f"  + {key[0]} {key[1]}")
            for key in removed:
                print(f"  - {key[0]} {key[1]}")

            # Field-level diff for routes that exist in both
            for key in set(new_routes) & set(existing_routes):
                old_fields = existing_routes[key].get("response_fields") or {}
                new_fields = new_routes[key].get("response_fields") or {}
                if old_fields != new_fields:
                    print(f"  ~ {key[0]} {key[1]}: response fields changed")
                    for f in set(new_fields) - set(old_fields):
                        print(f"      + field: {f}")
                    for f in set(old_fields) - set(new_fields):
                        print(f"      - field: {f}")

            sys.exit(1)

        print("OK: API contract matches api_contract.json")
        sys.exit(0)

    # Write mode
    CONTRACT_PATH.write_text(contract_json)
    print(f"Wrote {CONTRACT_PATH}")
    print(f"  Routes: {len(contract['routes'])}")


if __name__ == "__main__":
    main()
