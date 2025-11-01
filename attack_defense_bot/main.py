# ================================
# file: Maxin_attack_defense_bot/main.py
# ================================
"""
主入口：search → context → prompt → dialogue
- 遵循 a.docx 中的 API 说明
- API 客户端请统一使用 Maxin_attack_defense_bot.api_client.APIClient
- 配置请统一使用 Maxin_attack_defense_bot.config.Settings

用法：
  1) pip install requests
  2) python -m Maxin_attack_defense_bot.main --mode direct --query "防火墙的作用是什么？"
  3) python -m Maxin_attack_defense_bot.main --mode rag --db common_dataset --top-k 5 --query "如何防御SQL注入？"
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Dict, Optional

from . import get_logger, setup_logging
from .config import Settings, token_for_db
from .api_client import APIClient
from .data_processor import extract_context, files_to_citations
from .prompt_builder import build_prompt
from .guard import validate_user_input, validate_prompt

log = get_logger(__name__)


# -------------------- 流程 --------------------
def direct_dialogue_flow(api: APIClient, settings: Settings, query: str) -> Dict[str, Any]:
    ok, safe_text = validate_user_input(query)
    if not ok:
        return {"ok": False, "message": safe_text}

    custom_prompt = build_prompt(context="", mode="direct")
    ok, cp = validate_prompt(custom_prompt)
    if not ok:
        return {"ok": False, "message": cp}

    resp = api.dialogue(user_input=safe_text, token=settings.user_token, custom_prompt=cp)
    return _normalize_dialogue_output(resp)


def rag_dialogue_flow(api: APIClient, settings: Settings, query: str) -> Dict[str, Any]:
    ok, safe_text = validate_user_input(query)
    if not ok:
        return {"ok": False, "message": safe_text}

    # 检索用对应库的 token（公共库用 common token，其他库用 user token）
    token_for_this_db = token_for_db(settings.db_name, settings)

    search_resp = api.search(
        db_name=settings.db_name,
        query=safe_text,
        token=token_for_this_db,
        top_k=settings.top_k,
        metric_type=settings.metric_type,
        score_threshold=settings.score_threshold,
    )

    if search_resp.get("http_status") != 200 or search_resp.get("data", {}).get("status") != "success":
        return {"ok": False, "message": f"检索失败: {search_resp}"}

    # 提取上下文与引用
    context = extract_context(search_resp, max_chars=settings.max_ctx_chars)
    citations = files_to_citations(search_resp)

    custom_prompt = build_prompt(context=context, mode="rag")
    ok, cp = validate_prompt(custom_prompt)
    if not ok:
        return {"ok": False, "message": cp}

    # 对话通常使用个人/小组对话 token，这里沿用 settings.user_token
    resp = api.dialogue(user_input=safe_text, token=settings.user_token, custom_prompt=cp)
    result = _normalize_dialogue_output(resp)
    result["context_preview"] = context
    result["citations"] = citations
    return result


def _normalize_dialogue_output(resp: Dict[str, Any]) -> Dict[str, Any]:
    http_status = resp.get("http_status")
    data = resp.get("data", {})
    if http_status == 200 and data.get("status") == "success":
        return {"ok": True, "response": data.get("response", ""), "raw": data}
    return {"ok": False, "message": data, "raw": data}


# -------------------- CLI --------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="Maxin_attack_defense_bot",
        description="大模型安全实践：最小可用主入口（含 direct / rag 两条链路）",
    )
    p.add_argument("--mode", choices=["direct", "rag"], default="direct", help="对话模式")
    p.add_argument("--query", required=True, help="用户问题")
    p.add_argument("--db", default="common_dataset", help="RAG 模式下的数据库名，默认 common_dataset")
    p.add_argument("--metric", default="COSINE", help="相似度度量，默认 COSINE")
    p.add_argument("--top-k", type=int, default=5, help="RAG 检索数量")
    p.add_argument("--score-threshold", type=float, default=0.0, help="最小相似度阈值 0-1")
    p.add_argument("--max-ctx-chars", type=int, default=1600, help="上下文拼接的最大字符数")
    p.add_argument("--log-level", default="INFO", help="日志等级")
    p.add_argument("--expr", default=None, help="Milvus 过滤表达式，可选（保留参数位，当前未使用）")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    setup_logging(args.log_level)

    # 通过 Settings 统一读取默认配置与环境变量
    settings = Settings(
        db_name=args.db,
        metric_type=args.metric,
        top_k=args.top_k,
        score_threshold=args.score_threshold,
        max_ctx_chars=args.max_ctx_chars,
    )

    # 使用 settings.base_url，而不是任何 utils 常量，避免配置分散与重复
    api = APIClient(base_url=settings.base_url, timeout=settings.timeout)

    if args.mode == "direct":
        result = direct_dialogue_flow(api, settings, args.query)
    else:
        result = rag_dialogue_flow(api, settings, args.query)

    # 统一输出
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()