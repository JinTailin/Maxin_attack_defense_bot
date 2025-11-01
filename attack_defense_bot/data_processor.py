# ================================
# file: attack_defense_bot/data_processor.py
# ================================
from typing import List, Dict, Any

def extract_context(search_resp: Dict[str, Any], max_chars: int = 1600) -> str:
    """
    提炼上下文：从检索结果中提取相关文件并拼接成上下文字符串，限制字符数。
    """
    data = search_resp.get("data", {})
    files = data.get("files") or data.get("data") or data.get("results") or []
    if not isinstance(files, list):
        return ""
    
    # 筛掉相似性得分低于0.6的数据
    files = [item for item in files if item.get("score")>=0.6]

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


def files_to_citations(search_resp: Dict[str, Any]) -> str:
    """
    生成引用编号和链接，便于答案引用。
    假设返回的每个文件都有 file_id 和 metadata 信息。
    """
    data = search_resp.get("data", {})
    files = data.get("files") or data.get("data") or data.get("results") or []
    
    if not isinstance(files, list):
        return ""
    
    # 筛掉相似性得分低于0.6的数据
    files = [item for item in files if item.get("score")>=0.6]

    citations = []
    for i, item in enumerate(files, 1):
        file_id = item.get("file_id", f"doc#{i}")
        metadata = item.get("metadata", {})
        file_link = f"[{file_id}](http://yourfileserver/{file_id})"
        
        # 生成一个带有元数据的信息
        meta_info = ", ".join(f"{k}: {v}" for k, v in metadata.items())
        citation = f"[{i}] {file_link} ({meta_info})"
        citations.append(citation)

    return "\n".join(citations)
