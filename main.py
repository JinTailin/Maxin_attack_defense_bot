# ================================
# file: attack_defense_bot/main.py
# ================================
"""
主入口：search → context → prompt → dialogue
- 遵循 a.docx 中的 API 说明：
  - BASE_URL: http://10.1.0.220:9002/api
  - POST   /databases/{db}/search
  - POST   /dialogue（支持 custom_prompt + user_input）
- 仅依赖 requests，可直接运行；其他模块日后再拆分。

用法：
  1) pip install requests
  2) python -m attack_defense_bot.main --mode direct --query "防火墙的作用是什么？"
  3) python -m attack_defense_bot.main --mode rag --db common_dataset --top-k 5 --query "如何防御SQL注入？"
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests

from . import get_logger, setup_logging
from .config import Settings, token_for_db
from .api_client import APIClient

log = get_logger(__name__)

# ---------- 按你的要求：硬编码 token ----------
# 后端 API 前缀
BASE_URL = "http://10.1.0.220:9002/api"

# 你的组与个人 token
USER_TOKEN = "svrdAPQFp0I9K0VSeEa9G0Gvy9aU4vSbI8Ft4QKoRzRq0-K8ayGs4xKhdNmh8xzl"  # Group10

# 共享库配置（只读）
COMMON_DB_NAME = "common_dataset"
COMMON_DB_TOKEN = "token_common"

DEFAULT_METRIC = "COSINE"  # 文档是大写
TIMEOUT = 30


@dataclass
class Settings:
    base_url: str = BASE_URL
    user_token: str = USER_TOKEN
    common_db_token: str = COMMON_DB_TOKEN
    db_name: str = COMMON_DB_NAME
    metric_type: str = DEFAULT_METRIC
    timeout: int = TIMEOUT
    top_k: int = 5
    score_threshold: float = 0.0
    max_ctx_chars: int = 1600


# -------------------- 基础安全校验（最简后备实现） --------------------
def validate_user_input(text: str) -> Tuple[bool, str]:
    """
    返回：(通过与否, 处理后的文本或拒绝原因)
    """
    blacklist = [
        "payload",
        "rce",
        "反序列化利用",
        "木马",
        "注入语句",
        "爆破字典",
        "0day",
        "绕过waf",
    ]
    lowered = text.lower()
    if any(w in lowered for w in blacklist):
        return False, "你的问题涉及潜在攻击利用或敏感内容，我只能提供防御、检测与合规层面的信息。"
    return True, text.strip()


def validate_prompt(prompt: str) -> Tuple[bool, str]:
    if not prompt or len(prompt) < 5:
        return False, "生成的提示词过短或为空。"
    if len(prompt) > 8000:
        return False, "生成的提示词过长，超过安全阈值。"
    return True, prompt


# -------------------- Prompt 组装（结合 custom_prompt + user_input） --------------------
def build_custom_prompt(context: str, mode: str = "direct") -> str:
    boundary = (
        "【系统指令】你是一名网络安全助教，只提供防御、检测、合规与科普信息；"
        "对攻击利用、漏洞利用链、可复用攻击样例与敏感数据一律拒答。"
        "若不确定请明确说明，禁止编造。"
    )
    instructions = [
        boundary,
        f"【模式】{mode}",
        "【回答要求】结构化、分点说明；尽量引用来源编号 [1][2]；如需给出步骤，务必为防御/检测流程。",
    ]
    if context:
        instructions.append("【已知信息，仅可参考】\n" + context.strip())
    return "\n".join(instructions)


# -------------------- API 封装（按 a.docx） --------------------
class APIClient:
    def __init__(self, base_url: str, timeout: int = TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def dialogue(
        self,
        user_input: str,
        token: str,
        custom_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 300,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}/dialogue"
        payload: Dict[str, Any] = {
            "user_input": user_input,
            "token": token,
            "temperature": float(temperature),
            "max_tokens": int(max_tokens),
        }
        if custom_prompt:
            payload["custom_prompt"] = custom_prompt
        resp = self.session.post(url, headers=self.headers, json=payload, timeout=self.timeout)
        return _parse_response(resp)

    def search(
        self,
        db_name: str,
        query: str,
        token: str,
        top_k: int = 5,
        metric_type: str = DEFAULT_METRIC,
        score_threshold: float = 0.0,
        expr: Optional[str] = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}/databases/{db_name}/search"
        payload: Dict[str, Any] = {
            "token": token,
            "query": query,
            "top_k": int(top_k),
            "metric_type": (metric_type or DEFAULT_METRIC).upper(),
            "score_threshold": float(score_threshold),
        }
        if expr:
            payload["expr"] = expr
        resp = self.session.post(url, headers=self.headers, json=payload, timeout=self.timeout)
        return _parse_response(resp)


def _parse_response(resp: requests.Response) -> Dict[str, Any]:
    try:
        data = resp.json()
    except Exception:
        data = {"status": "error", "message": resp.text}
    return {"http_status": resp.status_code, "data": data}


# -------------------- RAG：检索结果转上下文 --------------------
def extract_context_from_search(search_resp: Dict[str, Any], max_chars: int = 1600) -> str:
    """
    按 a.docx：search 返回 data.files 列表
    每个元素包含 file_id / text / uploaded_at / metadata / score
    """
    data = search_resp.get("data", {})
    files = data.get("files") or data.get("data") or data.get("results") or []
    if not isinstance(files, list):
        return ""

    chunks: List[str] = []
    for i, item in enumerate(files, 1):
        text = str(item.get("text", "")).strip()
        src = item.get("file_id", f"doc#{i}")
        score = item.get("score", "")
        meta = item.get("metadata", {})
        meta_str = f" metadata={meta}" if meta else ""
        prefix = f"[{i}] 来源: {src} 分数: {score}{meta_str}"
        if text:
            chunks.append(prefix + "\n" + text)
    joined = "\n\n---\n\n".join(chunks)
    return joined[:max_chars] if len(joined) > max_chars else joined


# -------------------- 流程 --------------------
def direct_dialogue_flow(api: APIClient, settings: Settings, query: str) -> Dict[str, Any]:
    ok, safe_text = validate_user_input(query)
    if not ok:
        return {"ok": False, "message": safe_text}

    custom_prompt = build_custom_prompt(context="", mode="direct")
    ok, cp = validate_prompt(custom_prompt)
    if not ok:
        return {"ok": False, "message": cp}

    resp = api.dialogue(user_input=safe_text, token=settings.user_token, custom_prompt=cp)
    return _normalize_dialogue_output(resp)

def _token_for_db(db_name: str, settings: Settings) -> str:
    # 共享库名写死判断，避免把 COMMON_DB_NAME 改错
    if db_name.strip().lower() == "common_dataset":
        return settings.common_db_token
    return settings.user_token

def rag_dialogue_flow(api: APIClient, settings: Settings, query: str) -> Dict[str, Any]:
    ok, safe_text = validate_user_input(query)
    if not ok:
        return {"ok": False, "message": safe_text}

    
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

    context = extract_context_from_search(search_resp, max_chars=settings.max_ctx_chars)
    custom_prompt = build_custom_prompt(context=context, mode="rag")
    ok, cp = validate_prompt(custom_prompt)
    if not ok:
        return {"ok": False, "message": cp}

    # 对话仍使用你的个人 token
    resp = api.dialogue(user_input=safe_text, token=settings.user_token, custom_prompt=cp)
    result = _normalize_dialogue_output(resp)
    result["context_preview"] = context
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
        prog="attack_defense_bot",
        description="大模型安全实践：最小可用主入口（含 direct / rag 两条链路）",
    )
    p.add_argument("--mode", choices=["direct", "rag"], default="direct", help="对话模式")
    p.add_argument("--query", required=True, help="用户问题")
    p.add_argument("--db", default=COMMON_DB_NAME, help="RAG 模式下的数据库名，默认 common_dataset")
    p.add_argument("--metric", default=DEFAULT_METRIC, help="相似度度量，默认 cosine")
    p.add_argument("--top-k", type=int, default=5, help="RAG 检索数量")
    p.add_argument("--score-threshold", type=float, default=0.0, help="最小相似度阈值 0-1")
    p.add_argument("--max-ctx-chars", type=int, default=1600, help="上下文拼接的最大字符数")
    p.add_argument("--log-level", default="INFO", help="日志等级")
    p.add_argument("--expr", default=None, help="Milvus 过滤表达式，可选")
    return p.parse_args()


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

    api = APIClient(base_url=BASE_URL, timeout=settings.timeout)

    if args.mode == "direct":
        result = direct_dialogue_flow(api, settings, args.query)
    else:
        result = rag_dialogue_flow(api, settings, args.query)

    # 统一输出
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()