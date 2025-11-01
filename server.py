# -*- coding: utf-8 -*-
# file: server.py
from __future__ import annotations

import os
import sys
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# 添加项目路径（按你原有做法）
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 读取基础配置
from attack_defense_bot.utils import BASE_URL

# 从 main 引入你已经实现的多库 RAG 流程与 direct 流程
# 注：确保你的 main.py 暴露了 rag_dialogue_flow_multi 与 direct_dialogue_flow
from attack_defense_bot.main import (
    rag_dialogue_flow_multi,
    direct_dialogue_flow,
    APIClient,   # 延用你原本从 main 暴露的 APIClient
    Settings,    # 延用你原本从 main 暴露的 Settings
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
    # 模式：默认 rag（你的 index 未传 mode，这里保持兼容）
    mode: str = "rag"
    query: str

@app.post("/api/query")
async def query(request: QueryRequest):
    try:
        # 初始化设置和客户端
        settings = Settings()
        api = APIClient(base_url=BASE_URL)

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

# 提供前端页面（保持不变）
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