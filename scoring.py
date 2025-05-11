import hashlib
import json
from typing import Optional


def get_score(
    store,
    phone: Optional[str] = None,
    email: Optional[str] = None,
    birthday: Optional[str] = None,
    gender: Optional[int] = None,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
) -> float:
    key_parts = [
        first_name or "",
        last_name or "",
        str(phone) or "",
        birthday or "",
    ]
    key = "uid:" + hashlib.md5("".join(key_parts).encode("utf-8")).hexdigest()

    score = store.cache_get(key)
    if score is not None:
        return float(score)

    score = 0.0
    if phone:
        score += 1.5
    if email:
        score += 1.5
    if birthday and gender is not None:
        score += 1.5
    if first_name and last_name:
        score += 0.5

    store.cache_set(key, score, 60 * 60)
    return float(score)


def get_interests(store, cid: str) -> list:
    r = store.get(f"i:{cid}")
    return json.loads(r) if r else []
