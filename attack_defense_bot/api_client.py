from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests

from . import get_logger

log = get_logger(__name__)


def _parse_response(resp: requests.Response) -> Dict[str, Any]:
    try:
        data = resp.json()
    except Exception:
        data = {"status": "error", "message": resp.text}
    return {"http_status": resp.status_code, "data": data}


class APIClient:
    """
    a.docx 定义的后端 API 封装：
      - POST   /databases
      - GET    /databases
      - POST   /databases/{db}/files
      - GET    /databases/{db}/files
      - DELETE /databases/{db}/files/{file_id}
      - POST   /databases/{db}/search
      - POST   /dialogue
    注意：这里的 base_url 期望传入 .../api，不含末尾斜杠
    """

    def __init__(self, base_url: str, timeout: int = 30, session: Optional[requests.Session] = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    # ---------- 工具 ----------
    def _url(self, path: str) -> str:
        # 统一拼接，不重复 /
        return f"{self.base_url}{path}"

    # ---------- 数据库相关 ----------
    def create_database(self, database_name: str, token: str, metric_type: str = "COSINE") -> Dict[str, Any]:
        url = self._url("/databases")
        payload = {"database_name": database_name, "token": token, "metric_type": metric_type.upper()}
        resp = self.session.post(url, headers=self.headers, json=payload, timeout=self.timeout)
        return _parse_response(resp)

    def get_databases(self, token: str) -> Dict[str, Any]:
        url = self._url("/databases")
        resp = self.session.get(url, headers=self.headers, params={"token": token}, timeout=self.timeout)
        return _parse_response(resp)

    def upload_files(self, database_name: str, files: List[Dict[str, Any]], token: str) -> Dict[str, Any]:
        """
        files: [{"file": "文本内容", "metadata": {...}}, ...]
        """
        url = self._url(f"/databases/{database_name}/files")
        payload = {"files": files, "token": token}
        resp = self.session.post(url, headers=self.headers, json=payload, timeout=self.timeout)
        return _parse_response(resp)

    def get_files(self, database_name: str, token: str, offset: int = 0, limit: int = 100) -> Dict[str, Any]:
        url = self._url(f"/databases/{database_name}/files")
        params = {"token": token, "offset": int(offset), "limit": int(limit)}
        resp = self.session.get(url, headers=self.headers, params=params, timeout=self.timeout)
        return _parse_response(resp)

    def delete_file(self, database_name: str, file_id: str, token: str) -> Dict[str, Any]:
        url = self._url(f"/databases/{database_name}/files/{file_id}")
        resp = self.session.delete(url, headers=self.headers, params={"token": token}, timeout=self.timeout)
        return _parse_response(resp)

    # ---------- 检索与对话 ----------
    def search(
        self,
        db_name: str,
        query: str,
        token: str,
        top_k: int = 10,
        metric_type: str = "COSINE",
        score_threshold: float = 0.0,
        expr: Optional[str] = None,
    ) -> Dict[str, Any]:
        url = self._url(f"/databases/{db_name}/search")
        payload: Dict[str, Any] = {
            "token": token,
            "query": query,
            "top_k": int(top_k),
            "metric_type": (metric_type or "COSINE").upper(),
            "score_threshold": float(score_threshold),
        }
        if expr:
            payload["expr"] = expr
        resp = self.session.post(url, headers=self.headers, json=payload, timeout=self.timeout)
        return _parse_response(resp)

    # 可选：更直观的别名
    def search_files(
        self, database_name: str, token: str, query: str, top_k: int = 10,
        metric_type: str = "COSINE", score_threshold: float = 0.0, expr: Optional[str] = None
    ) -> Dict[str, Any]:
        return self.search(
            db_name=database_name,
            query=query,
            token=token,
            top_k=top_k,
            metric_type=metric_type,
            score_threshold=score_threshold,
            expr=expr,
        )

    def dialogue(
        self,
        user_input: str,
        token: str,
        custom_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 150,
    ) -> Dict[str, Any]:
        """
        对话（a.docx）
        - 支持 custom_prompt 注入系统安全指令
        """
        url = self._url("/dialogue")
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

