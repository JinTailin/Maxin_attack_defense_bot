from typing import List, Dict, Any, Tuple
import hashlib

CAND_SOURCE_KEYS = [
    "file_id", "document_id", "doc_id", "doc_hash",
    "source", "path", "url", "uri", "filename", "name",
]

def _pick_source_key(hit: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
    """
    返回 (db, key, meta)
    - db: 来自 metadata["__db"] 或 metadata["db"]
    - key: 尽量稳定的“文档级”标识；若都没有，用文本hash兜底，避免误并
    """
    meta = dict(hit.get("metadata") or {})
    db = str(meta.get("__db") or meta.get("db") or "")
    # 在 hit 顶层和 metadata 里都尝试
    for k in CAND_SOURCE_KEYS:
        v = hit.get(k)
        if v:
            return db, str(v), meta
        v = meta.get(k)
        if v:
            return db, str(v), meta
    # 兜底：用前 200 字生成稳定 hash，避免不同文档被误并
    txt = str(hit.get("text") or hit.get("content") or "")[:200]
    h = hashlib.md5(txt.encode("utf-8")).hexdigest() if txt else hashlib.md5(str(hit).encode("utf-8")).hexdigest()
    return db, f"UNKNOWN#{h}", meta

def merge_hits_by_source(
    search_resp: Dict[str, Any],
    *,
    score_threshold: float = 0.6,
    per_chunk_max: int = 300,
    per_source_max: int = 800,
    max_ctx_chars: int = 1600,
) -> Dict[str, Any]:
    """
    将检索命中按"同一来源"聚合，生成：
    - context: 合并后的上下文（控制总长）
    - citations: 去重后的引用列表 [{index,title,section,source,score}]
    - citations_str: 字符串格式的引用（保持与之前代码兼容）
    - groups: 内部分组的详细结构（可用于调试）
    """
    data = (search_resp or {}).get("data", {}) or {}
    hits: List[Dict[str, Any]] = data.get("files") or data.get("results") or data.get("data") or []
    if not isinstance(hits, list):
        return {"context": "", "citations": [], "citations_str": "", "groups": []}

    # 过滤
    hits = [h for h in hits if float(h.get("score") or 0.0) >= score_threshold]
    if not hits:
        return {"context": "", "citations": [], "citations_str": "", "groups": []}

    # 分组
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for h in hits:
        db, key, meta = _pick_source_key(h)
        g = groups.setdefault((db, key), {"db": db, "key": key, "meta": meta, "score": 0.0, "texts": []})
        sc = float(h.get("score") or 0.0)
        g["score"] = max(g["score"], sc)
        txt = str(h.get("text") or h.get("content") or "").strip()
        if txt:
            # 轻度截断，避免某段过长
            if len(txt) > per_chunk_max:
                txt = txt[:per_chunk_max]
            g["texts"].append((sc, txt))

    # 组内排序 + 限额
    merged_blocks: List[str] = []
    merged_groups: List[Dict[str, Any]] = []
    for (db, key), g in groups.items():
        g["texts"].sort(key=lambda t: t[0], reverse=True)
        buf, used = [], 0
        for sc, tx in g["texts"]:
            if used + len(tx) + 1 > per_source_max:
                break
            buf.append(tx)
            used += len(tx) + 1
        if not buf:
            continue
        merged_groups.append({
            "db": db,
            "key": key,
            "meta": g["meta"],
            "score": g["score"],
            "text": "\n".join(buf),
        })

    # 跨来源按得分排序，拼装 context
    merged_groups.sort(key=lambda x: x["score"], reverse=True)
    blocks = []
    for i, g in enumerate(merged_groups, 1):
        title = g["meta"].get("title") or g["meta"].get("filename") or g["key"]
        src = g["db"] or g["meta"].get("source") or ""
        head = f"[{i}] {title}（来源: {src} | 分数: {round(g['score'], 4)}）"
        blocks.append(head + "\n" + g["text"])
    context = "\n\n---\n\n".join(blocks)
    if len(context) > max_ctx_chars:
        context = context[:max_ctx_chars]

    # 引用数组（前端可直接展示）
    citations = []
    for i, g in enumerate(merged_groups, 1):
        meta = g["meta"] or {}
        citations.append({
            "index": i,
            "title": meta.get("title") or meta.get("filename") or g["key"],
            "section": meta.get("section") or "",
            "source": g["db"] or meta.get("source") or "",
            "score": round(g["score"], 4),
        })

    # 生成字符串格式的引用
    citations_str_lines = []
    for i, g in enumerate(merged_groups, 1):
        meta = g["meta"] or {}
        title = meta.get("title") or meta.get("filename") or g["key"]
        source = g["db"] or meta.get("source") or ""
        section = meta.get("section") or ""
        
        # 构建引用字符串行
        line = f"[{i}] {title}"
        if section:
            line += f" (section: {section})"
        if source:
            line += f" (source: {source})"
        if g["score"] > 0:
            line += f" (score: {round(g['score'], 4)})"
            
        citations_str_lines.append(line)
    
    citations_str = "\n".join(citations_str_lines)

    return {
        "context": context, 
        "citations": citations, 
        "citations_str": citations_str,
        "groups": merged_groups
    }

def extract_context(search_resp: Dict[str, Any], max_chars: int = 1600) -> str:
    """
    提炼上下文：合并同一来源（按 __db + file_id 分组），避免把一条来源拆成多段。
    仍保留相似性过滤（score >= 0.6），并限制每来源与总体的注入长度。
    """
    data = (search_resp or {}).get("data", {}) or {}
    files = data.get("files") or data.get("data") or data.get("results") or []
    if not isinstance(files, list):
        return ""

    # 1) 过滤低分
    filt = [it for it in files if float(it.get("score") or 0.0) >= 0.6]
    if not filt:
        return ""

    # 2) 按 (db, file_id) 分组聚合
    #    db 取 metadata["__db"]（若无则空字符串，避免误并）
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for idx, it in enumerate(filt, 1):
        meta = dict(it.get("metadata") or {})
        db = str(meta.get("__db") or meta.get("db") or "")
        fid = str(it.get("file_id") or meta.get("file_id") or f"doc#{idx}")
        key = (db, fid)

        g = groups.setdefault(key, {
            "db": db, "file_id": fid, "meta": meta, "scores": [], "texts": []
        })

        sc = float(it.get("score") or 0.0)
        txt = str(it.get("text") or it.get("content") or "").strip()
        if txt:
            g["scores"].append(sc)
            g["texts"].append((sc, txt))

    # 3) 组内按得分降序，拼接若干段落（限制每来源的最大注入长度）
    PER_CHUNK_MAX = 400      # 单段截断
    PER_SOURCE_MAX = 800     # 每来源总上限（字符）
    merged: List[Dict[str, Any]] = []
    for (_, _), g in groups.items():
        g["texts"].sort(key=lambda t: t[0], reverse=True)
        buf, used = [], 0
        for sc, tx in g["texts"]:
            # 轻度截断，避免单段过长
            if len(tx) > PER_CHUNK_MAX:
                tx = tx[:PER_CHUNK_MAX]
            if used + len(tx) + 1 > PER_SOURCE_MAX:
                break
            buf.append(tx)
            used += len(tx) + 1

        if not buf:
            continue

        merged.append({
            "db": g["db"],
            "file_id": g["file_id"],
            "meta": g["meta"],
            "score": max(g["scores"]) if g["scores"] else 0.0,
            "text": "\n".join(buf)
        })

    if not merged:
        return ""

    # 4) 跨来源按最高分排序并封装为可读块，最后整体按 max_chars 截断
    merged.sort(key=lambda x: x["score"], reverse=True)

    chunks: List[str] = []
    for i, m in enumerate(merged, 1):
        meta_str = f" metadata={m['meta']}" if m.get("meta") else ""
        db_hint = f"（__db: {m['db']}）" if m.get("db") else ""
        prefix = f"[{i}] 来源: {m['file_id']}{db_hint} 分数: {round(m['score'], 4)}{meta_str}"
        chunks.append(prefix + "\n" + m["text"])

    joined = "\n\n---\n\n".join(chunks)
    return joined[:max_chars] if len(joined) > max_chars else joined


def files_to_citations(search_resp: Dict[str, Any]) -> str:
    """
    生成引用列表（去重版）：同一来源（__db + file_id）仅保留一次，取最高得分并合并元数据。
    返回多行字符串，便于前端折叠显示为“来源 1/2/3 …”
    """
    data = (search_resp or {}).get("data", {}) or {}
    files = data.get("files") or data.get("data") or data.get("results") or []
    if not isinstance(files, list):
        return ""

    filt = [it for it in files if float(it.get("score") or 0.0) >= 0.6]
    if not filt:
        return ""

    uniq: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for it in filt:
        meta = dict(it.get("metadata") or {})
        db = str(meta.get("__db") or meta.get("db") or "")
        fid = str(it.get("file_id") or meta.get("file_id") or "doc")
        key = (db, fid)
        sc = float(it.get("score") or 0.0)

        if key not in uniq or sc > uniq[key]["score"]:
            uniq[key] = {"db": db, "file_id": fid, "score": sc, "meta": meta}
        else:
            # 合并元数据（后者覆盖前者）
            uniq[key]["meta"] = {**uniq[key]["meta"], **meta}

    rows: List[str] = []
    ordered = sorted(uniq.values(), key=lambda x: x["score"], reverse=True)
    for i, u in enumerate(ordered, 1):
        file_link = f"[{u['file_id']}](http://yourfileserver/{u['file_id']})"
        meta = dict(u.get("meta") or {})
        if u.get("db"):
            meta.setdefault("__db", u["db"])
        meta_info = ", ".join(f"{k}: {v}" for k, v in meta.items()) if meta else ""
        rows.append(f"[{i}] {file_link} ({meta_info})")

    return "\n".join(rows)