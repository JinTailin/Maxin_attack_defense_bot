"""
用途
- 从 data 目录读取 TXT（可选含 MD）语料，清洗/切分/去噪/去重，并上传到指定 DB
- 默认仅处理 .txt；如需 .md，添加 --include-md
- 即使使用 --recreate 也会“保留 JSONL/MCQ 上传的数据”（例如 ingest_jsonl_mcq.py 上传的内容）
- 根据课件建议做优化：每块加入摘要与伪问句锚点；只保留中文占比达阈值的块；关键词写入 metadata

用法示例
1) 仅上传 TXT，保留 JSONL 数据（推荐）
   python scripts/ingest_data_dir_safe.py --db student_Group10_corpus --data-dir data --recreate --batch-size 30 --verbose

2) 包含 MD
   python scripts/ingest_data_dir_safe.py --db student_Group10_corpus --data-dir data --include-md --recreate --batch-size 30

3) 仅构建不上传（排查）
   python scripts/ingest_data_dir_safe.py --db student_Group10_corpus --data-dir data --dry-run --preview 6 --verbose
"""

import os
import re
import glob
import json
import argparse
import html
import time
import locale
import hashlib
from typing import List, Dict, Any, Tuple

# -------- 兼容两套包名 --------
try:
    from attack_defense_bot.config import Settings, token_for_db
    from attack_defense_bot.api_client import APIClient
    PKG_NAME = "attack_defense_bot"
except Exception:
    from Maxin_attack_defense_bot.config import Settings, token_for_db
    from Maxin_attack_defense_bot.api_client import APIClient
    PKG_NAME = "Maxin_attack_defense_bot"


def ts():
    return time.strftime("%H:%M:%S")


def log(msg: str, level: str = "INFO", verbose: bool = False, force: bool = False):
    if level == "DEBUG" and not (verbose or force):
        return
    print(f"[{ts()}] {level:<5} {msg}", flush=True)


def human(n: int) -> str:
    if n < 1000:
        return f"{n}"
    if n < 10000:
        return f"{n/1000:.1f}K"
    if n < 1000_000:
        return f"{n/1000:.0f}K"
    return f"{n/1000_000:.1f}M"


# -------- 基础清洗与切分 --------
RE_FUNC_FIX = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\(\s*\)")
RE_CODE_FENCE = re.compile(r"```.*?```", re.S)
RE_SENT_SPLIT = re.compile(r"(?<=[。！？!?；;\n])")
RE_HEX_SECTION = re.compile(r"^\s*0x[0-9A-Fa-f]{2,}\s*[\.\u3002]?\s*(.+?)\s*$")
RE_SHORT_CN_TITLE = re.compile(r"^\s*[（(]?\s*[第]?[零一二三四五六七八九十0-9xX]{1,5}\s*[章节部分篇]\s*[）)]?\s*.+$")
RE_CJK = re.compile(r"[\u4e00-\u9fff]")

NOISE_LINES = [
    "All Rights Reserved", "©", "上一篇", "下一篇",
    "首页 安全公告 披露原则 关于 English", "腾讯玄武实验室",
]

KEYWORDS_CANDIDATES = [
    "CVE", "CSRF", "SSRF", "XSS", "SQLi", "LFI", "RCE",
    "NTLM", "Kerberos", "TLS", "HTTPS", "DNS", "SMB",
    "Domain Fronting", "Domain Borrowing", "Wi‑Fi", "USB",
    "BadPower", "快充", "长度侧信道", "Ghidra", "XFA",
]


def clean_text(s: str) -> str:
    s = s.replace("\r\n", "\n").replace("\r", "\n").strip("\ufeff")
    s = html.unescape(s)
    lines = [ln for ln in s.split("\n") if not any(noise in ln for noise in NOISE_LINES)]
    s = "\n".join(lines)
    s = re.sub(r"\n{3,}", "\n\n", s).strip()
    return s


def normalize_functions(s: str) -> str:
    return RE_FUNC_FIX.sub(lambda m: f"{m.group(1)}()", s)


def split_sentences(s: str) -> List[str]:
    parts = [p.strip() for p in RE_SENT_SPLIT.split(s) if p and p.strip()]
    return parts if parts else [s.strip()]


def _hard_slice(text: str, size: int, overlap: int) -> List[str]:
    stride = max(1, size - max(0, overlap))
    return [text[i:i + size] for i in range(0, len(text), stride)]


def sliding_window(sentences: List[str], max_chars: int, overlap: int) -> List[str]:
    if not sentences:
        return []
    chunks: List[str] = []
    cur, cur_len, i = [], 0, 0
    while i < len(sentences):
        seg = sentences[i]
        if len(seg) > max_chars:
            if cur:
                chunks.append("".join(cur).strip())
                if overlap > 0:
                    tail = chunks[-1][-overlap:]
                    cur, cur_len = [tail], len(tail)
                else:
                    cur, cur_len = [], 0
            chunks.extend(_hard_slice(seg, max_chars, overlap))
            i += 1
            continue
        if (cur_len + len(seg)) <= max_chars or not cur:
            cur.append(seg)
            cur_len += len(seg)
            i += 1
        else:
            text = "".join(cur).strip()
            if text:
                chunks.append(text)
            if overlap > 0 and text:
                tail = text[-overlap:]
                cur, cur_len = [tail], len(tail)
            else:
                cur, cur_len = [], 0
    text = "".join(cur).strip()
    if text:
        chunks.append(text)
    return chunks


def shortlist_keywords(text: str) -> List[str]:
    kws = set()
    for m in re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text):
        kws.add(m)
    for m in re.findall(r"\b[A-Z]{2,}(?:[-_/][A-Z0-9]{2,})*\b", text):
        if not m.isdigit():
            kws.add(m)
    for kw in KEYWORDS_CANDIDATES:
        if kw in text:
            kws.add(kw)
    out = sorted(kws)
    return out[:15] if len(out) > 15 else out


def detect_sections(text: str) -> List[Tuple[str, str]]:
    lines = text.split("\n")
    sections: List[Tuple[str, List[str]]] = []
    cur_title, cur_buf = None, []

    def flush():
        nonlocal cur_title, cur_buf, sections
        body = "\n".join(cur_buf).strip()
        if body:
            sections.append((cur_title or "正文", body))
        cur_title, cur_buf = None, []

    for ln in lines:
        t = ln.strip()
        m_hex = RE_HEX_SECTION.match(t)
        if m_hex:
            flush()
            cur_title = "0x" + re.findall(r"0x[0-9A-Fa-f]{2,}", t)[0] + " " + m_hex.group(1)
            continue
        if (RE_SHORT_CN_TITLE.match(t) or (len(t) <= 32 and re.match(r"^\s*\d{1,2}[\.、]\s*\S", t))) and len(t) <= 32:
            flush()
            cur_title = t
            continue
        if any(t.startswith(h) for h in ["背景", "问题", "漏洞", "总结", "防御", "建议"]) and len(t) <= 32:
            flush()
            cur_title = t
            continue
        cur_buf.append(ln)
    flush()
    return [(t, b) for t, b in sections if b and len(b) > 50]


# -------- 摘要 + 伪问句 --------
def chinese_ratio(s: str) -> float:
    if not s:
        return 0.0
    cjk = len(RE_CJK.findall(s))
    return cjk / max(len(s), 1)


def make_summary(title: str, section: str | None, text: str, max_len: int = 180) -> str:
    # 简要摘要：标题/小节 + 前两句，截断到 max_len
    first_two = "".join(split_sentences(text)[:2]).strip()
    head = f"{section or title}：".strip("：")
    summ = f"{head} {first_two}" if first_two else head
    return (summ[:max_len] + "…") if len(summ) > max_len else summ


def pseudo_questions(title: str, section: str | None, text: str, k: int = 3) -> List[str]:
    topic = (section or title or "该主题").strip()
    qs: List[str] = []
    qs.append(f"什么是{topic}？")
    if any(x in text for x in ["步骤", "方法", "复现", "利用", "配置", "部署"]):
        qs.append(f"如何实现/复现{topic}？")
    else:
        qs.append(f"{topic}的关键原理是什么？")
    if any(x in text for x in ["防护", "防御", "修复", "加固", "缓解", "建议"]):
        qs.append(f"{topic}的防护/加固建议有哪些？")
    else:
        qs.append(f"{topic}存在哪些风险与影响？")
    return qs[:k]


# -------- I/O 与编码 --------
def _decode_with_candidates(data: bytes, prefer: str) -> Tuple[str, str]:
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
    seen, ordered = set(), []
    for enc in candidates:
        e = enc.lower()
        if e not in seen:
            ordered.append(e)
            seen.add(e)
    last_err = None
    for enc in ordered:
        try:
            return data.decode(enc), enc
        except Exception as e:
            last_err = e
            continue
    return data.decode("utf-8", errors="replace"), "utf-8(replace)"


def read_text_file(path: str, prefer_encoding: str = "auto") -> Tuple[str, str]:
    with open(path, "rb") as f:
        data = f.read()
    return _decode_with_candidates(data, prefer=prefer_encoding)


def collect_files(data_dir: str, include_md: bool) -> List[str]:
    pats = [os.path.join(data_dir, "**", "*.txt")]
    if include_md:
        pats.append(os.path.join(data_dir, "**", "*.md"))
    paths: List[str] = []
    for p in pats:
        paths.extend(glob.glob(p, recursive=True))
    return [p for p in sorted(set(paths)) if os.path.isfile(p)]


# -------- 构建块 --------
def chunk_paragraph(text: str, max_chars: int, overlap: int) -> List[str]:
    text = text.strip()
    if not text:
        return []
    if len(text) <= max_chars:
        return [text]
    parts = sliding_window(split_sentences(text), max_chars, overlap)
    out: List[str] = []
    for p in parts:
        if len(p) > max_chars:
            out.extend(_hard_slice(p, max_chars, overlap))
        else:
            out.append(p)
    return out


def choose_and_chunk(raw: str, title: str, max_chars: int, overlap: int,
                     min_cn_ratio: float, max_summary_chars: int) -> List[Dict[str, Any]]:
    raw = clean_text(normalize_functions(raw))
    sections = detect_sections(raw)
    pieces: List[Dict[str, Any]] = []

    def make_item(sec_title: str | None, body: str, idx_in_sec: int | None):
        body_wo_fence = RE_CODE_FENCE.sub(" [代码示例略] ", body)
        for k, piece in enumerate(chunk_paragraph(body_wo_fence, max_chars, overlap)):
            if chinese_ratio(piece) < min_cn_ratio:
                continue
            summ = make_summary(title, sec_title, piece, max_len=max_summary_chars)
            anchors = pseudo_questions(title, sec_title, piece, k=3)
            text = []
            text.append(f"【文档】{title}")
            if sec_title:
                text.append(f"【小节】{sec_title}")
            text.append(f"【摘要】{summ}")
            text.append(piece.strip())
            text.append(f"【伪问】" + " | ".join(anchors))
            content = "\n".join(text)
            meta = {
                "title": title,
                "section": sec_title or "",
                "summary": summ,
                "pseudo_q": anchors,
                "idx_in_section": k if idx_in_sec is not None else k,
            }
            pieces.append({"content": content, "metadata": meta})

    if sections:
        for i, (sec_title, body) in enumerate(sections):
            make_item(sec_title, body, i)
    else:
        make_item(None, raw, None)
    return pieces


def sig(text: str) -> str:
    # 轻量去重签名：大小写归一、去多空格、数字归一
    t = text.lower()
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"\d+", "#", t)
    return hashlib.sha1(t.encode("utf-8")).hexdigest()


# -------- 主流程 --------
def parse_args():
    ap = argparse.ArgumentParser(description="读取 data 目录 TXT 语料，优化构建并上传（保留 JSONL/MCQ 数据）")
    ap.add_argument("--db", required=True, help="数据库名，如 student_Group10_corpus")
    ap.add_argument("--data-dir", default="data", help="语料目录（默认 data）")
    ap.add_argument("--include-md", action="store_true", help="除 TXT 外，同时处理 .md 文件")
    ap.add_argument("--max-chars", type=int, default=600, help="chunk 最大字符数（建议 500–700）")
    ap.add_argument("--overlap", type=int, default=100, help="chunk 重叠字符数")
    ap.add_argument("--min-chinese-ratio", type=float, default=0.15, help="块内中文字符比例下限，低于此值将跳过")
    ap.add_argument("--max-summary-chars", type=int, default=180, help="摘要最大长度（字符）")
    ap.add_argument("--recreate", action="store_true", help="上传前清理旧 TXT/MD 内容（保留 JSONL/MCQ）")
    ap.add_argument("--recreate-all", action="store_true", help="危险：无差别删除库内全部文件（包括 JSONL/MCQ）")
    ap.add_argument("--batch-size", type=int, default=40, help="上传批大小")
    ap.add_argument("--preview", type=int, default=6, help="打印前 N 个预览")
    ap.add_argument("--max-files", type=int, default=0, help="仅处理前 N 个文件（0 表示全部）")
    ap.add_argument("--dry-run", action="store_true", help="仅构建不上传")
    ap.add_argument("--verbose", action="store_true", help="打印 DEBUG 日志")
    ap.add_argument("--encoding", default="auto", help="文件编码：auto/utf-8/gbk/gb18030/utf-16 等")
    return ap.parse_args()


def main():
    args = parse_args()
    s = Settings()
    if os.name == "nt":
        log("Windows 提示：若 PowerShell 显示乱码，使用 Get-Content -Encoding UTF8；CMD 先 chcp 65001。", "INFO")
    api = APIClient(base_url=s.base_url, timeout=s.timeout)
    token = token_for_db(args.db, s)

    log(f"环境: pkg={PKG_NAME}, base_url={s.base_url}, timeout={s.timeout}s, locale={locale.getpreferredencoding(False)}", "INFO")
    log(f"参数: db={args.db}, data_dir={args.data_dir}, include_md={args.include_md}, max_chars={args.max_chars}, "
        f"overlap={args.overlap}, min_cn_ratio={args.min_chinese_ratio}, recreate={args.recreate}, "
        f"recreate_all={args.recreate_all}, batch={args.batch_size}, preview={args.preview}, encoding={args.encoding}", "INFO")

    # 收集文件
    paths = collect_files(args.data_dir, include_md=args.include_md)
    if args.max_files and len(paths) > args.max_files:
        paths = paths[:args.max_files]
    if not paths:
        print(json.dumps({"ok": False, "message": f"未在 {args.data_dir} 下找到 .txt（或 --include-md 时的 .md）文件"}, ensure_ascii=False))
        return
    log(f"发现 TXT/MD 文件：{len(paths)} 个", "INFO")
    for p in paths[:10]:
        log(f"  - {p}", "DEBUG", verbose=args.verbose)

    # 读取与构建
    t0 = time.perf_counter()
    all_payload: List[Dict[str, Any]] = []
    total_chars = 0
    seen_sigs = set()
    per_file_stats = []

    for i, p in enumerate(paths, 1):
        t_file = time.perf_counter()
        try:
            raw, enc = read_text_file(p, prefer_encoding=args.encoding)
        except Exception as e:
            log(f"[{i}/{len(paths)}] 读取失败：{p} -> {e}", "ERROR", force=True)
            continue
        total_chars += len(raw)
        title = os.path.splitext(os.path.basename(p))[0]

        t_ck = time.perf_counter()
        chunks = choose_and_chunk(
            raw, title=title, max_chars=args.max_chars, overlap=args.overlap,
            min_cn_ratio=args.min_chinese_ratio, max_summary_chars=args.max_summary_chars
        )
        ck_ms = (time.perf_counter() - t_ck) * 1000

        kept = 0
        for ch in chunks:
            text = ch["content"]
            meta = ch["metadata"] or {}
            meta.update({"source": p, "encoding": enc})
            kws = shortlist_keywords(text)
            if kws:
                meta["keywords"] = kws

            signature = sig(text)
            if signature in seen_sigs:
                continue
            seen_sigs.add(signature)

            all_payload.append({"file": text, "metadata": meta})
            kept += 1

        log(f"[{i}/{len(paths)}] 读取{round((time.perf_counter()-t_file)*1000)}ms 切分{round(ck_ms)}ms - "
            f"{os.path.basename(p)} (enc={enc}, chars={human(len(raw))}, chunks={len(chunks)}, kept={kept})", "INFO")

        per_file_stats.append({
            "path": p, "encoding": enc, "chars": len(raw),
            "chunks": len(chunks), "kept": kept
        })

    log(f"构建完成：文件={len(paths)}，总字符≈{human(total_chars)}，去重后 chunk={len(all_payload)}，耗时={(time.perf_counter()-t0):.2f}s", "INFO")

    # 预览
    for i, it in enumerate(all_payload[:max(0, min(args.preview, len(all_payload)))]):
        log(f"--- 预览 chunk #{i} ---", "DEBUG", verbose=args.verbose)
        if args.verbose:
            print(it["file"][:500] + ("..." if len(it["file"]) > 500 else ""))
            print("metadata:", json.dumps(it["metadata"], ensure_ascii=False))

    if args.dry_run:
        print(json.dumps({
            "ok": True, "dry_run": True,
            "files": len(paths), "total_chars": total_chars,
            "total_chunks": len(all_payload), "preview": min(args.preview, len(all_payload)),
            "per_file_stats": per_file_stats[:10],
        }, ensure_ascii=False, indent=2))
        return

    # 安全清理（仅 TXT/MD），除非 --recreate-all
    if args.recreate or args.recreate_all:
        log("准备清理旧内容…", "INFO")
        try:
            existing = api.get_files(args.db, token, offset=0, limit=1000)
            files = (existing.get("data", {}) or {}).get("files") or []
        except Exception as e:
            log(f"列出现有文件失败：{e}", "ERROR", force=True)
            files = []
        del_cnt, skip_cnt = 0, 0
        for it in files:
            fid = str(it.get("file_id") or "")
            meta = it.get("metadata") or {}
            src = str(meta.get("source") or "").lower()
            typ = str(meta.get("type") or "")
            title = str(meta.get("title") or "")

            # 策略：
            # - 默认“保留 JSONL/MCQ”（source 以 .jsonl 结尾，或 type=='mcq'，或标题含“选择题”）
            # - 仅删除来源为 .txt/.md 或无来源的旧块
            keep_jsonl = (src.endswith(".jsonl") or typ == "mcq" or "选择题" in title)

            should_delete = True
            if not args.recreate_all and keep_jsonl:
                should_delete = False
            if args.recreate and not args.recreate_all:
                # 仅删 txt/md 源
                if src and (not src.endswith(".txt") and not src.endswith(".md")):
                    should_delete = False

            if not should_delete:
                skip_cnt += 1
                continue

            if not fid:
                continue
            try:
                api.delete_file(args.db, fid, token)
                del_cnt += 1
            except Exception as e:
                log(f"删除 file_id={fid} 失败：{e}", "WARN")

        log(f"清理完成：删除 {del_cnt} 条，跳过(保留) {skip_cnt} 条", "INFO")

    # 上传
    if not all_payload:
        print(json.dumps({"ok": False, "message": "没有可上传的块"}, ensure_ascii=False))
        return

    B = max(1, int(args.batch_size))
    total_batches = (len(all_payload) + B - 1) // B
    uploaded, slow = 0, 0
    log(f"开始上传：chunks={len(all_payload)}，batch={B}", "INFO")
    for i in range(0, len(all_payload), B):
        batch = all_payload[i:i + B]
        cur = (i // B) + 1
        log(f"↑ 上传批次 {cur}/{total_batches}（size={len(batch)}）…", "INFO")
        t_b = time.perf_counter()
        try:
            api.upload_files(args.db, batch, token)
        except Exception as e:
            log(f"批次 {cur} 上传失败：{e}", "ERROR", force=True)
            return
        dt = (time.perf_counter() - t_b) * 1000
        uploaded += len(batch)
        spd = len(batch) / max(dt / 1000.0, 1e-3)
        lvl = "INFO" if dt <= 3000 else "WARN"
        if lvl == "WARN":
            slow += 1
        log(f"✓ 批次 {cur} 完成：{round(dt)}ms，{spd:.1f} items/s（累计 {uploaded}/{len(all_payload)}）", lvl)

    print(json.dumps({"ok": True, "uploaded": uploaded, "batches": total_batches, "slow_batches": slow}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
