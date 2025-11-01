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
  4) 自动选择（检索为空则回退到 direct）：
     python -m Maxin_attack_defense_bot.main --mode auto --db student_Group10_corpus --query "RLE4 解析"
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Dict, Optional, List

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


def rag_dialogue_flow(
    api: APIClient,
    settings: Settings,
    query: str,
    expr: Optional[str] = None,
    fallback_to_direct: bool = False,
) -> Dict[str, Any]:
    """
    RAG 对话流：
    - 支持 expr 过滤（Milvus 表达式）
    - 支持检索为空或上下文为空时回退 direct，避免“冷场”
    - 对检索结果做简单日志采样
    """
    ok, safe_text = validate_user_input(query)
    if not ok:
        return {"ok": False, "message": safe_text}

    # 检索用对应库 token
    token_for_this_db = token_for_db(settings.db_name, settings)

    search_resp = api.search(
        db_name=settings.db_name,
        query=safe_text,
        token=token_for_this_db,
        top_k=settings.top_k,
        metric_type=settings.metric_type,
        score_threshold=settings.score_threshold,
        expr=expr,
    )

    if search_resp.get("http_status") != 200 or search_resp.get("data", {}).get("status") != "success":
        if fallback_to_direct:
            log.warning("检索失败，回退 direct：%s", search_resp)
            return direct_dialogue_flow(api, settings, query)
        return {"ok": False, "message": f"检索失败: {search_resp}"}

    # 简单日志：命中数量与前3个分数
    data = search_resp.get("data", {}) or {}
    hits: List[Dict[str, Any]] = data.get("files") or data.get("results") or data.get("data") or []
    scores = [round(float(h.get("score", 0.0)), 4) for h in hits[:3]]
    log.info("retrieved=%d, top_scores=%s, threshold=%.3f", len(hits), scores, settings.score_threshold)

    if not hits and fallback_to_direct:
        log.info("检索为空，回退 direct")
        return direct_dialogue_flow(api, settings, query)

    # 提取上下文与引用
    context = extract_context(search_resp, max_chars=settings.max_ctx_chars)
    citations = files_to_citations(search_resp)

    if (not context) and fallback_to_direct:
        log.info("检索有结果但上下文为空（可能都被阈值过滤），回退 direct")
        return direct_dialogue_flow(api, settings, query)

    custom_prompt = build_prompt(context=context, mode="rag")
    ok, cp = validate_prompt(custom_prompt)
    if not ok:
        if fallback_to_direct:
            log.warning("Prompt 校验失败，回退 direct：%s", cp)
            return direct_dialogue_flow(api, settings, query)
        return {"ok": False, "message": cp}

    # 对话通常使用个人/小组对话 token
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
        description="大模型安全实践：direct / rag / auto / multi-rag"
    )
    p.add_argument("--mode", choices=["direct", "rag", "auto"], default="direct", help="对话模式")
    p.add_argument("--query", required=True, help="用户问题")
    p.add_argument("--dbs", default=None, help="逗号分隔的多个库名，用于多库检索，如: db1,db2")
    p.add_argument("--metric", default="COSINE", help="相似度度量，默认 COSINE")
    p.add_argument("--top-k-total", type=int, default=None, help="多库合并后截断的总 top_k；默认=每库top_k×库数")
    p.add_argument("--score-threshold", type=float, default=0.0, help="最小相似度阈值 0-1")
    p.add_argument("--max-ctx-chars", type=int, default=1600, help="上下文拼接的最大字符数")
    p.add_argument("--expr", default=None, help="Milvus 过滤表达式，可选")
    p.add_argument("--client-timeout", type=int, default=None, help="HTTP 客户端超时（秒），默认沿用 Settings.timeout")
    p.add_argument("--log-level", default="INFO", help="日志等级")
    p.add_argument("--no-fallback", action="store_true", help="RAG 失败或空结果时不回退 direct")
    return p.parse_args()

# 2) 工具函数：从 search 响应提取 hits，打上来源库标记
def _hits_from_search(db_name: str, search_resp: Dict[str, Any]) -> List[Dict[str, Any]]:
    data = search_resp.get("data", {}) or {}
    hits = data.get("files") or data.get("results") or data.get("data") or []
    out = []
    for h in hits:
        # 统一字段，并标记来源库，方便引用展示
        hh = dict(h)
        meta = dict(hh.get("metadata") or {})
        meta["__db"] = db_name
        hh["metadata"] = meta
        # 确保 score 为 float
        try:
            hh["score"] = float(hh.get("score", 0.0))
        except Exception:
            hh["score"] = 0.0
        out.append(hh)
    return out

# 3) 可选：对每个库内分数做 min-max 归一化，避免不同库阈值/尺度差异
def _minmax_norm(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not hits:
        return hits
    scores = [h["score"] for h in hits]
    mn, mx = min(scores), max(scores)
    if mx <= mn:
        return hits
    for h in hits:
        h["score"] = (h["score"] - mn) / (mx - mn)
    return hits

# 4) 多库 RAG 主流程：对每个库检索，合并、排序、截断
def rag_dialogue_flow_multi(
    api: APIClient,
    settings: Settings,
    query: str,
    dbs: List[str],
    expr: Optional[str] = None,
    fallback_to_direct: bool = True,
    per_db_top_k: Optional[int] = None,
    total_top_k: Optional[int] = None,
    normalize_each_db: bool = True,
) -> Dict[str, Any]:
    ok, safe_text = validate_user_input(query)
    if not ok:
        return {"ok": False, "message": safe_text}

    dbs = [d.strip() for d in dbs if d and d.strip()]
    if not dbs:
        return {"ok": False, "message": "未提供有效的库名列表"}

    per_k = per_db_top_k or settings.top_k
    all_hits: List[Dict[str, Any]] = []
    any_fail = False

    for db in dbs:
        token = token_for_db(db, settings)
        resp = api.search(
            db_name=db,
            query=safe_text,
            token=token,
            top_k=per_k,
            metric_type=settings.metric_type,
            score_threshold=settings.score_threshold,
            expr=expr,
        )
        ok_http = resp.get("http_status") == 200 and (resp.get("data", {}) or {}).get("status") == "success"
        if not ok_http:
            any_fail = True
            # 不中断，继续其它库
            log.warning("库 %s 检索失败：%s", db, resp)
            continue

        hits = _hits_from_search(db, resp)
        # 可选：库内 min-max 归一化，使不同库分数可比
        if normalize_each_db:
            hits = _minmax_norm(hits)
        # 记录每库日志
        log.info("DB=%s retrieved=%d, top_scores=%s", db, len(hits), [round(h.get("score", 0.0), 4) for h in hits[:3]])
        all_hits.extend(hits)

    if not all_hits:
        if fallback_to_direct:
            msg = "多库均无命中" + ("（包含失败）" if any_fail else "")
            log.info("%s，回退 direct", msg)
            return direct_dialogue_flow(api, settings, query)
        return {"ok": False, "message": "多库检索均为空"}

    # 合并后排序与截断
    all_hits.sort(key=lambda h: h.get("score", 0.0), reverse=True)
    # 默认总 top_k = 每库 top_k × 库数；也可显式设置 total_top_k
    cap = total_top_k or (per_k * len(dbs))
    merged = all_hits[:cap]

    # 构造一个“合成的检索响应”喂给 extract_context / files_to_citations
    merged_resp = {
        "http_status": 200,
        "data": {
            "status": "success",
            "files": merged
        }
    }

    context = extract_context(merged_resp, max_chars=settings.max_ctx_chars)
    citations = files_to_citations(merged_resp)

    if (not context) and fallback_to_direct:
        log.info("合并后上下文为空（可能被阈值过滤），回退 direct")
        return direct_dialogue_flow(api, settings, query)

    custom_prompt = build_prompt(context=context, mode="rag")
    ok, cp = validate_prompt(custom_prompt)
    if not ok:
        if fallback_to_direct:
            log.warning("Prompt 校验失败，回退 direct：%s", cp)
            return direct_dialogue_flow(api, settings, query)
        return {"ok": False, "message": cp}

    resp = api.dialogue(user_input=safe_text, token=settings.user_token, custom_prompt=cp)
    result = _normalize_dialogue_output(resp)
    result["context_preview"] = context
    result["citations"] = citations
    result["from_dbs"] = dbs
    return result


def main() -> None:
    args = parse_args()
    setup_logging(args.log_level)
    settings = Settings(
        db_name=args.db,
        metric_type=args.metric,
        top_k=args.top_k,
        score_threshold=args.score_threshold,
        max_ctx_chars=args.max_ctx_chars,
    )
    timeout = settings.timeout if args.client_timeout is None else int(args.client_timeout)
    api = APIClient(base_url=settings.base_url, timeout=timeout)

    # 解析多库
    dbs: List[str] = []
    if args.dbs:
        dbs = [d.strip() for d in args.dbs.split(",") if d.strip()]

    if args.mode == "direct":
        result = direct_dialogue_flow(api, settings, args.query)
    elif args.mode in ("rag", "auto"):
        if len(dbs) >= 2:
            # 多库检索
            result = rag_dialogue_flow_multi(
                api, settings, args.query,
                dbs=dbs,
                expr=args.expr,
                fallback_to_direct=(args.mode == "auto" and not args.no_fallback),
                per_db_top_k=args.top_k,
                total_top_k=args.top_k_total,
                normalize_each_db=True
            )
        else:
            # 单库检索（原逻辑）
            result = rag_dialogue_flow(
                api, settings, args.query, expr=args.expr,
                fallback_to_direct=(args.mode == "auto" and not args.no_fallback)
            )
    else:
        # 兜底
        result = direct_dialogue_flow(api, settings, args.query)

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()