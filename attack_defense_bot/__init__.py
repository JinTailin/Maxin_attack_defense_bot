"""
attack_defense_bot
- 包初始化：统一日志、版本号、便捷 logger
"""

from __future__ import annotations

import logging
import os
from typing import Optional

__all__ = ["__version__", "setup_logging", "get_logger"]
__version__ = "0.1.0"


def setup_logging(level: Optional[str] = None) -> None:
    level_name = (level or os.getenv("ATTACK_BOT_LOG_LEVEL", "INFO")).upper()
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=getattr(logging, level_name, logging.INFO),
            format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    else:
        logging.getLogger().setLevel(getattr(logging, level_name, logging.INFO))

    # 降噪
    for noisy in ("urllib3", "requests"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: Optional[str] = None) -> logging.Logger:
    return logging.getLogger(name or "attack_defense_bot")


# import 即初始化一次日志
setup_logging()
