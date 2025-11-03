from __future__ import annotations

import os
import sys
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# 添加项目路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 读取基础配置
from attack_defense_bot.utils import BASE_URL

# 从 main 引入已经实现的多库 RAG 流程与 direct 流程
# 注：确保 main.py 暴露了 rag_dialogue_flow_multi 与 direct_dialogue_flow
from attack_defense_bot.main import (
    rag_dialogue_flow_multi,
    direct_dialogue_flow,
    APIClient,   # 延用从 main 暴露的 APIClient
    Settings,    # 延用从 main 暴露的 Settings
)

app = FastAPI(title="安全AI助手 API")

# 允许跨域（保持与原来一致）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class QueryRequest(BaseModel):
    # 模式：默认 rag
    mode: str = "rag"
    query: str

def is_smalltalk(q: str) -> bool:
    q = (q or "").strip().lower()
    if len(q) <= 3:
        return True
    small = ["你好", "在吗", "谢谢", "哈哈", "嗨", "hello", "hi", "ok", "好的", "？", "我是人", "你是谁", "我是谁", "测试"]
    return any(s in q for s in small)

def is_security_topic(q: str) -> bool:
    ql = (q or "").lower()
    kws = [
        "安全", "防火墙", "入侵", "攻击", "漏洞", "补丁", "xss", "sql", "注入", "csrf", "rce", "越权",
        "口令", "弱口令", "加密", "解密", "权限", "渗透", "端口", "审计", "日志", "合规", "等保",
        "waf", "ids", "ips", "ddos", "木马", "勒索", "钓鱼", "蜜罐", "沙箱", "威胁情报"
    ]
    return any(k in ql for k in kws)

def should_use_rag(q: str) -> bool:
    # 闲聊或非安全主题 -> 不用 RAG
    if is_smalltalk(q):
        return False
    if not is_security_topic(q):
        return False
    return True

@app.post("/api/query")
async def query(request: QueryRequest):
    try:
        settings = Settings()
        # 轻量收紧，减少误注入（可按需调整/注释）
        settings.top_k = 3
        settings.score_threshold = max(getattr(settings, "score_threshold", 0.0), 0.5)
        settings.max_ctx_chars = min(getattr(settings, "max_ctx_chars", 1600), 1000)

        api = APIClient(base_url=settings.base_url, timeout=settings.timeout)

        mode = (request.mode or "auto").lower()

        # 显式 direct 仍走 direct
        if mode == "direct":
            return JSONResponse(direct_dialogue_flow(api, settings, request.query), 200)

        # 意图路由
        if not should_use_rag(request.query):
            # 非安全/闲聊 -> 不查库，给出简短引导式回复
            return JSONResponse(direct_dialogue_flow(api, settings, request.query), 200)

        # 默认两个库：自建库 + 通用库（可通过环境变量覆盖）
        primary_db = os.getenv("RAG_PRIMARY_DB", "student_Group10_corpus")
        fallback_db = os.getenv("RAG_FALLBACK_DB", "common_dataset")
        dbs: List[str] = [primary_db, fallback_db]

        mode = (request.mode or "rag").lower()

        # 显式 direct 则不查库
        if mode == "direct":
            result = direct_dialogue_flow(api, settings, request.query)
            return JSONResponse(content=result, status_code=200)

        # 其余情况（rag/auto）统一走多库检索并合并
        # auto 语义：命中为空时回退 direct；rag 语义：不回退
        fallback_to_direct = (mode == "auto")

        result = rag_dialogue_flow_multi(
            api=api,
            settings=settings,
            query=request.query,
            dbs=dbs,
            expr=None,
            fallback_to_direct=fallback_to_direct,
        )
        return JSONResponse(content=result, status_code=200)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 提供前端页面
@app.get("/")
async def read_index():
    here = os.path.dirname(os.path.abspath(__file__))
    index_path = os.path.join(here, "index.html")
    if not os.path.exists(index_path):
        return JSONResponse({"error": "index.html not found"}, status_code=404)
    return FileResponse(index_path)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)