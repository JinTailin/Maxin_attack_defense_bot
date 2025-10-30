from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uvicorn
import sys
import os

# 添加项目路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from attack_defense_bot.main import rag_dialogue_flow, APIClient, Settings

app = FastAPI(title="安全AI助手 API")

# 允许跨域
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class QueryRequest(BaseModel):
    mode: str = "rag"
    query: str

@app.post("/api/query")
async def query(request: QueryRequest):
    try:
        # 初始化设置和客户端
        settings = Settings()
        api = APIClient(base_url="http://10.1.0.220:9002/api")
        
        # 调用 RAG 流程
        result = rag_dialogue_flow(api, settings, request.query)
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 添加这个路由来提供前端页面
@app.get("/")
async def read_index():
    return FileResponse('index.html')

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
