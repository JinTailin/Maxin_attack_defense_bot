# file: Maxin_attack_defense_bot/config.py
from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import get_logger

log = get_logger(__name__)

DEFAULT_BASE_URL = "http://10.1.0.220:9002/api"
DEFAULT_DB_COMMON = "common_dataset"
DEFAULT_COMMON_TOKEN = "token_common"
DEFAULT_METRIC = "COSINE"
DEFAULT_TIMEOUT = 30
DEFAULT_TOPK = 5
DEFAULT_SCORE_THRESHOLD = 0.0
DEFAULT_MAX_CTX_CHARS = 1600

GROUP10_USER_TOKEN = "svrdAPQFp0I9K0VSeEa9G0Gvy9aU4vSbI8Ft4QKoRzRq0-K8ayGs4xKhdNmh8xzl"

def _env(key: str, default: str) -> str:
    val = os.getenv(key)
    return val if val is not None and str(val).strip() != "" else default

@dataclass
class Settings:
    # 注意：使用 default_factory，实例化时才读取环境变量
    base_url: str = field(default_factory=lambda: _env("ATTACK_BOT_BASE_URL", DEFAULT_BASE_URL))
    user_token: str = field(default_factory=lambda: _env("ATTACK_BOT_USER_TOKEN", GROUP10_USER_TOKEN))
    common_db_token: str = field(default_factory=lambda: _env("ATTACK_BOT_COMMON_DB_TOKEN", DEFAULT_COMMON_TOKEN))
    db_name: str = field(default_factory=lambda: _env("ATTACK_BOT_DEFAULT_DB", DEFAULT_DB_COMMON))
    metric_type: str = field(default_factory=lambda: _env("ATTACK_BOT_DEFAULT_METRIC", DEFAULT_METRIC))
    timeout: int = field(default_factory=lambda: int(_env("ATTACK_BOT_TIMEOUT", str(DEFAULT_TIMEOUT))))
    top_k: int = field(default_factory=lambda: int(_env("ATTACK_BOT_TOPK", str(DEFAULT_TOPK))))
    score_threshold: float = field(default_factory=lambda: float(_env("ATTACK_BOT_SCORE_THRESHOLD", str(DEFAULT_SCORE_THRESHOLD))))
    max_ctx_chars: int = field(default_factory=lambda: int(_env("ATTACK_BOT_MAX_CTX_CHARS", str(DEFAULT_MAX_CTX_CHARS))))

    def __post_init__(self):
        # 统一大写 metric
        self.metric_type = (self.metric_type or DEFAULT_METRIC).upper()

def token_for_db(db_name: str, settings: Settings) -> str:
    if db_name.strip().lower() == DEFAULT_DB_COMMON:
        return settings.common_db_token
    return settings.user_token