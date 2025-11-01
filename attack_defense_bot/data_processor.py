# ================================
# file: attack_defense_bot/data_processor.py
# ================================
from typing import List, Dict, Any, Tuple

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