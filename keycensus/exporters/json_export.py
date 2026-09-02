import json

from ..model import Inventory


def render(inv: Inventory) -> str:
    return json.dumps(inv.to_dict(), indent=2, default=str) + "\n"
