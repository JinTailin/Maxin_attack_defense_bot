"""
读取 JSONL 语料（每行一条 JSON），仅上传 language 为 Chinese 的样本。
每条样本会被转换为中文块文本，并携带丰富的 metadata，批量上传到指定 DB。

用法示例：
  1) 预览前 5 条，不上传（排查样本格式）
     python scripts/ingest_jsonl_mcq.py --db student_Group10_corpus --jsonl a.jsonl b.jsonl --preview 5 --dry-run --verbose

  2) 清库后上传，两份语料合并，批大小 100
     python scripts/ingest_jsonl_mcq.py --db student_Group10_corpus --jsonl a.jsonl b.jsonl --recreate --batch-size 100 --verbose

注意：
- 仅处理 language 为 Chinese 的样本，其余跳过
- 支持单/多答案（label 可为 "A"/["A","C"]），答案文本将合并写入标准答案行
"""

import os
import sys
import json
import time
import argparse
import hashlib
import locale
from typing import List, Dict, Any, Tuple, Iterable

# -------- 兼容两套包名 --------
try:
    from attack_defense_bot.config import Settings, token_for_db
    from attack_defense_bot.api_client import APIClient
    PKG_NAME = "attack_defense_bot"
except Exception:
    from Maxin_attack_defense_bot.config import Settings, token_for_db
    from Maxin_attack_defense_bot.api_client import APIClient
    PKG_NAME = "Maxin_attack_defense_bot"

# -------- 轻量日志 --------
def ts():
    return time.strftime("%H:%M:%S")

def log(msg: str, level: str = "INFO", verbose: bool = False, force: bool = False):
    if level == "DEBUG" and not (verbose or force):
        return
    print(f"[{ts()}] {level:<5} {msg}", flush=True)

# -------- 字符工具 --------
ABC = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def ensure_list(v) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]

def to_upper_letters(x) -> List[str]:
    if isinstance(x, str):
        return [x.strip().upper()]
    if isinstance(x, list):
        return [str(i).strip().upper() for i in x]
    return []

def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()

# -------- 读取 JSONL（带容错） --------
def _decode_with_candidates(data: bytes, prefer: str) -> Tuple[str, str]:
    # BOM 优先
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig"), "utf-8-sig"
    if data.startswith(b"\xff\xfe"):
        try:
            return data.decode("utf-16-le"), "utf-16-le"
        except Exception:
            pass
    if data.startswith(b"\xfe\xff"):
        try:
            return data.decode("utf-16-be"), "utf-16-be"
        except Exception:
            pass
    candidates = []
    if prefer and prefer.lower() != "auto":
        candidates.append(prefer)
    candidates.extend([
        "utf-8",
        locale.getpreferredencoding(False) or "cp936",
        "gb18030", "gbk",
        "utf-16", "utf-16-le", "utf-16-be",
    ])
    seen = set(); ordered = []
    for enc in candidates:
        e = enc.lower()
        if e not in seen:
            seen.add(e); ordered.append(e)
    last_err = None
    for enc in ordered:
        try:
            return data.decode(enc), enc
        except Exception as e:
            last_err = e
            continue
    return data.decode("utf-8", errors="replace"), "utf-8(replace)"

def read_jsonl(path: str, encoding: str = "auto", verbose: bool = False) -> Iterable[Dict[str, Any]]:
    with open(path, "rb") as f:
        raw = f.read()
    txt, enc = _decode_with_candidates(raw, encoding)
    ok = 0; bad = 0
    for i, line in enumerate(txt.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            ok += 1
            yield obj
        except Exception as e:
            bad += 1
            if verbose:
                log(f"[{os.path.basename(path)}] 第 {i} 行 JSON 解析失败：{e} | {line[:120]}", "WARN", verbose=True)
            continue
    log(f"读取 {os.path.basename(path)}：有效 {ok} 条，解析失败 {bad} 条（enc={enc}）", "INFO")

# -------- 构建上传项（仅中文样本） --------
def build_item(rec: Dict[str, Any], source_path: str) -> Dict[str, Any] | None:
    # 仅接受中文
    lang = str(rec.get("language") or "").strip().lower()
    if lang not in {"chinese", "zh", "zh-cn", "zh_cn", "中文"}:
        return None

    q = str(rec.get("question") or "").strip()
    answers = ensure_list(rec.get("answers"))
    domain = (rec.get("domain") or "").strip() or "未标注领域"
    ability = (rec.get("ability") or "").strip() or "知识记忆"
    labels = to_upper_letters(rec.get("label"))

    if not q or not answers:
        return None

    # 允许任意选项数（A..Z），超出则截断
    letters = [ABC[i] for i in range(min(len(answers), len(ABC)))]

    # 组装“标准答案文本”
    idxs = []
    for L in labels:
        if L in letters:
            idxs.append(letters.index(L))
    answer_texts = [str(answers[i]).strip() for i in idxs if 0 <= i < len(answers)]
    answer_text = "；".join(answer_texts) if answer_texts else ""

    # 中文块文本（面向检索）
    lines = []
    lines.append(f"【类型】单项选择题")
    lines.append(f"【领域】{domain}")
    lines.append(f"【能力】{ability}")
    lines.append(f"【题目】{q}")
    lines.append("【选项】")
    for L, opt in zip(letters, answers):
        lines.append(f"{L}. {str(opt).strip()}")
    if answer_text:
        lines.append(f"【标准答案】{answer_text}（选项{','.join(labels) or '?'}）")
    content = "\n".join(lines).strip()

    # metadata
    meta: Dict[str, Any] = {
        "title": f"选择题-{domain}",
        "section": ability,
        "source": source_path,
        "domain": domain,
        "ability": ability,
        "label": labels if len(labels) != 1 else labels[0],
        "answer_text": answer_text,
        "language": "Chinese",
        "type": "mcq",
        "doc_id": sha1(q + "|" + os.path.basename(source_path)),
    }
    # 便于规则/expr 过滤
    if answer_text:
        meta["keywords"] = list({domain, ability, "选择题", "标准答案", answer_text})

    return {"file": content, "metadata": meta}

# -------- 主流程 --------
def parse_args():
    ap = argparse.ArgumentParser(description="上传 JSONL 问答语料（仅中文）")
    ap.add_argument("--db", required=True, help="目标数据库名")
    ap.add_argument("--jsonl", nargs="+", required=True, help="一个或多个 .jsonl 文件")
    ap.add_argument("--batch-size", type=int, default=80, help="上传批大小")
    ap.add_argument("--recreate", action="store_true", help="上传前清空库")
    ap.add_argument("--preview", type=int, default=5, help="打印前 N 条构建预览")
    ap.add_argument("--max-items", type=int, default=0, help="最多处理前 N 条（0 表示全部）")
    ap.add_argument("--dry-run", action="store_true", help="仅构建不上传")
    ap.add_argument("--encoding", default="auto", help="文件编码（auto/utf-8/gb18030/…）")
    ap.add_argument("--verbose", action="store_true", help="打印调试信息")
    return ap.parse_args()

def main():
    args = parse_args()
    s = Settings()
    api = APIClient(base_url=s.base_url, timeout=s.timeout)
    token = "svrdAPQFp0I9K0VSeEa9G0Gvy9aU4vSbI8Ft4QKoRzRq0-K8ayGs4xKhdNmh8xzl"

    log(f"环境: pkg={PKG_NAME}, base_url={s.base_url}, timeout={s.timeout}s", "INFO")
    log(f"参数: db={args.db}, files={len(args.jsonl)}, batch={args.batch_size}, recreate={args.recreate}, preview={args.preview}, dry_run={args.dry_run}", "INFO")

    # 收集样本
    t0 = time.perf_counter()
    records: List[Dict[str, Any]] = []
    total_lines = 0
    for p in args.jsonl:
        if not os.path.isfile(p):
            log(f"文件不存在：{p}", "ERROR", force=True)
            continue
        for rec in read_jsonl(p, encoding=args.encoding, verbose=args.verbose):
            total_lines += 1
            item = build_item(rec, p)
            if item:
                records.append(item)
    if args.max_items and len(records) > args.max_items:
        records = records[:args.max_items]

    log(f"样本统计：读取行数={total_lines}，中文有效样本={len(records)}，耗时={(time.perf_counter()-t0):.2f}s", "INFO")

    # 预览
    for i, it in enumerate(records[:max(0, min(args.preview, len(records)))]):
        log(f"--- 预览 #{i} ---", "DEBUG", verbose=args.verbose)
        if args.verbose:
            print(it["file"])
            print("metadata:", json.dumps(it["metadata"], ensure_ascii=False))

    if args.dry_run:
        print(json.dumps({
            "ok": True,
            "dry_run": True,
            "valid_items": len(records),
            "total_lines": total_lines,
            "preview": min(args.preview, len(records)),
        }, ensure_ascii=False, indent=2))
        return

    # 可选清库
    if args.recreate:
        log("准备清空目标库中的旧文件…", "INFO")
        try:
            existing = api.get_files(args.db, token, offset=0, limit=1000)
            files = (existing.get("data", {}) or {}).get("files") or []
        except Exception as e:
            log(f"列出现有文件失败：{e}", "ERROR", force=True)
            files = []
        del_cnt = 0
        for it in files:
            fid = str(it.get("file_id") or "")
            if not fid:
                continue
            try:
                api.delete_file(args.db, fid, token)
                del_cnt += 1
            except Exception as e:
                log(f"删除 file_id={fid} 失败：{e}", "WARN")
        log(f"清空完成：删除 {del_cnt} 条", "INFO")

    # 上传
    if not records:
        print(json.dumps({"ok": False, "message": "没有可上传的中文样本"}, ensure_ascii=False))
        return

    B = max(1, int(args.batch_size))
    total_batches = (len(records) + B - 1) // B
    uploaded = 0
    slow = 0
    t_up = time.perf_counter()
    log(f"开始上传：items={len(records)}，batch={B}", "INFO")
    for i in range(0, len(records), B):
        batch = records[i:i+B]
        cur_no = (i // B) + 1
        t_b = time.perf_counter()
        log(f"↑ 上传批次 {cur_no}/{total_batches}（size={len(batch)}）…", "INFO")
        try:
            api.upload_files(args.db, batch, token)
        except Exception as e:
            log(f"批次 {cur_no} 上传失败：{e}", "ERROR", force=True)
            # 打印一个样本辅助排障
            try:
                log(f"失败样本 metadata: {json.dumps(batch[0].get('metadata', {}), ensure_ascii=False)}", "DEBUG", verbose=True, force=True)
            except Exception:
                pass
            return
        dt_ms = (time.perf_counter() - t_b) * 1000
        if dt_ms > 3000:
            slow += 1
            lvl = "WARN"
        else:
            lvl = "INFO"
        uploaded += len(batch)
        spd = len(batch) / max(dt_ms / 1000.0, 1e-3)
        log(f"✓ 批次 {cur_no} 完成：{round(dt_ms)}ms，{spd:.1f} items/s（累计 {uploaded}/{len(records)}）", lvl)

    log(f"上传完成：slow_batches={slow}/{total_batches}，耗时={(time.perf_counter()-t_up):.2f}s", "INFO")
    print(json.dumps({"ok": True, "uploaded": uploaded, "batches": total_batches}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
