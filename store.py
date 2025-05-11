from redis import Redis
from redis.backoff import NoBackoff
from redis.retry import Retry


class RedisStore:
    def __init__(self, host: str, port: int) -> None:
        self.retry: NoBackoff = Retry(NoBackoff(), 3)
        self.redis: Redis = Redis(
            host=host,
            port=port,
            socket_connect_timeout=0.1,
            retry=self.retry,
            retry_on_timeout=True,
        )

    def get(self, key: str) -> str:
        value: bytes = self.redis.get(key)
        if not value:
            return None
        return value.decode("utf-8")

    def cache_get(self, key: str) -> str:
        value: bytes = self.redis.get(key)
        if not value:
            return None
        return value.decode("utf-8")

    def cache_set(self, key: str, value: str, expired: int) -> None:
        self.redis.set(key, value, ex=expired)
