
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
功能（增强：编码自动识别 + 详细进度与耗时诊断）
- 自动读取 data 目录下所有 .txt/.md 文件（可递归）
- 编码处理：优先检测 BOM，失败则按候选集自动尝试（utf-8/gb18030/gbk/utf-16 等）
- 清洗（去导航/版权噪声、空白规范、函数名括号规范）
- 结构化切分（中文小节/0xNN 标题优先；否则句子滑窗）
- 关键词仅写入 metadata（不会写入正文）
- 详细阶段耗时统计：发现文件、读取、切分、上传
- 批量上传进度：每批开始/完成时间、吞吐、慢批告警
- 可选择仅构建不上传（--dry-run）
- 可强制指定编码（--encoding），默认 auto

使用示例
  1) 首次构建并清空库后上传（推荐先加 --preview 验证切分）
     python scripts/ingest_data_dir.py --db student_Group10_corpus --data-dir data --max-chars 700 --overlap 120 --recreate --preview 8 --verbose
  2) 只构建不上传（排查切分速度/文本量）
     python scripts/ingest_data_dir.py --db student_Group10_corpus --data-dir data --dry-run --verbose
  3) 如遇编码问题，强制指定（例如 gb18030）
     python scripts/ingest_data_dir.py --db student_Group10_corpus --data-dir data --encoding gb18030 --dry-run --verbose
"""

import os
import re
import glob
import json
import argparse
import html
import time
import locale
from typing import List, Dict, Any, Tuple

# -------- 兼容两套模块命名 --------
try:
    from attack_defense_bot.config import Settings, token_for_db
    from attack_defense_bot.api_client import APIClient
    PKG_NAME = "attack_defense_bot"
except Exception:
    from Maxin_attack_defense_bot.config import Settings, token_for_db
    from Maxin_attack_defense_bot.api_client import APIClient
    PKG_NAME = "Maxin_attack_defense_bot"

# -------- 轻量日志工具 --------
def ts():
    return time.strftime("%H:%M:%S")

def log(msg: str, level: str="INFO", verbose=False, force=False):
    if level == "DEBUG" and not (verbose or force):
        return
    print(f"[{ts()}] {level:<5} {msg}", flush=True)

def human(n: int) -> str:
    if n < 1000: return f"{n}"
    if n < 10000: return f"{n/1000:.1f}K"
    if n < 1000_000: return f"{n/1000:.0f}K"
    return f"{n/1000_000:.1f}M"

# -------- 基础正则与词表 --------
RE_FUNC_FIX = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\(\s*\)")
RE_SENT_SPLIT = re.compile(r"(?<=[。！？!?；;])")
RE_CODE_FENCE = re.compile(r"```.*?```", re.S)

# 常见中文小节标题（覆盖中文技术文章的常见风格）
CN_HEADINGS = [
    "背景", "问题简介", "技术背景", "问题描述", "影响后果", "影响范围", "安全建议",
    "总结", "参考资料", "环境搭建", "位图简介", "RLE 编码", "漏洞分析", "漏洞利用",
    "利用技巧", "防御方法", "案例", "复现步骤", "经验教训", "真实世界的攻击演示",
    "总结与安全提醒",
]
RE_HEX_SECTION = re.compile(r"^\s*0x[0-9A-Fa-f]{2,}\s*[\.\u3002]?\s*(.+?)\s*$")
RE_SHORT_CN_TITLE = re.compile(r"^\s*[（(]?\s*[第]?[零一二三四五六七八九十0-9xX]{1,5}\s*[章节部分篇]\s*[）)]?\s*.+$")

# 明显站点导航/版权等噪声
NOISE_LINES = [
    "腾讯玄武实验室", "首页 安全公告 披露原则 关于 English",
    "All Rights Reserved", "©", "上一篇", "下一篇",
]

# 领域关键词候选（仅入 metadata）
KEYWORDS_CANDIDATES = [
    "反调试", "反篡改", "代码混淆", "完整性检查", "代码签名", "堆溢出", "整数溢出",
    "DNS", "SNI", "ESNI", "TLS", "TLSv1.3", "HTTPS", "HTTP", "TCP", "UDP", "NAT",
    "SEQ", "ACK", "Challenge ACK", "AnyCast", "Client Hello",
    "Domain Fronting", "Domain Borrowing", "Domain Hiding",
    "Cloudflare", "AWS CloudFront", "Google Cloud CDN", "Fastly", "StackPath", "CDN77",
    "BootstrapCDN", "FontAwesome", "Palo Alto", "Anti-Spyware",
    "DNS Rebind", "GCDWebServer", "127.0.0.1", "本地端口", "同源策略",
    "RLE8", "RLE4", "XFA", "ArrayBuffer", "DataView", "ObjectElements",
    "CVE", "CVE-2019-8014", "CVE-2013-2729", "XXE", "NTLM", "NTLM Relay", "SSRF",
    "SMB", "SpiderMonkey",
    "BadPower", "快充", "USB", "Type-C", "PD", "固件", "过压", "20V",
    "长度侧信道", "5G", "4G", "LTE", "RCS", "Wi-Fi",
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

# 将句子分割扩大到包含换行
RE_SENT_SPLIT = re.compile(r"(?<=[。！？!?；;\n])")

def split_sentences(s: str) -> List[str]:
    # 优先按中文标点+换行切分
    parts = [p.strip() for p in RE_SENT_SPLIT.split(s) if p and p.strip()]
    # 若文本没有任何这些边界，至少保证返回一个元素（原样返回）
    return parts if parts else [s.strip()]

def _hard_slice(text: str, size: int, overlap: int) -> List[str]:
    """对超长文本做硬切，按 size 切片，步长为 size-overlap。"""
    if size <= 0:
        size = 500
    stride = max(1, size - max(0, overlap))
    out = []
    for i in range(0, len(text), stride):
        out.append(text[i:i+size])
    return out

def sliding_window(sentences: List[str], max_chars: int, overlap: int) -> List[str]:
    """
    安全版滑窗：
    - 若句子长度本身 > max_chars，则对该句子做硬切，保证能前进 i。
    - 否则正常累积，满了就输出 chunk，并用“尾部字符”回填 overlap。
    - 绝不出现 i 不递增的情况。
    """
    if not sentences:
        return []

    chunks: List[str] = []
    cur_parts: List[str] = []
    cur_len = 0
    i = 0
    long_seg_warned = 0

    while i < len(sentences):
        seg = sentences[i]

        # 1) 处理“超长句”
        if len(seg) > max_chars:
            # 先把当前缓冲吐出
            if cur_parts:
                chunks.append("".join(cur_parts).strip())
                # 用尾部字符回填 overlap
                if overlap > 0:
                    tail = chunks[-1][-overlap:]
                    cur_parts = [tail]
                    cur_len = len(tail)
                else:
                    cur_parts, cur_len = [], 0

            # 对这句硬切，直接落盘
            for piece in _hard_slice(seg, max_chars, overlap):
                chunks.append(piece.strip())
            i += 1  # 关键：推进 i，避免死循环

            # 告警一次（最多告警 3 次，避免刷屏）
            if long_seg_warned < 3:
                print(f"[WARN] 遇到超长句（len={len(seg)} > max_chars={max_chars}），已按固定长度切分。")
                long_seg_warned += 1
            continue

        # 2) 普通累积逻辑
        if (cur_len + len(seg)) <= max_chars or not cur_parts:
            cur_parts.append(seg)
            cur_len += len(seg)
            i += 1  # 正常推进
        else:
            # 输出当前 chunk
            text = "".join(cur_parts).strip()
            if text:
                chunks.append(text)
            # 用尾部字符回填 overlap，准备继续处理同一个 seg（注意：seg 本身 <= max_chars，不会死循环）
            if overlap > 0 and len(text) > 0:
                tail = text[-overlap:]
                cur_parts = [tail]
                cur_len = len(tail)
            else:
                cur_parts, cur_len = [], 0

    # 3) 收尾
    text = "".join(cur_parts).strip()
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

# -------- 标题识别与切分 --------
def detect_sections(text: str) -> List[Tuple[str, str]]:
    lines = text.split("\n")
    sections: List[Tuple[str, List[str]]] = []
    cur_title = None
    cur_buf: List[str] = []

    def flush():
        nonlocal cur_title, cur_buf, sections
        body = "\n".join(cur_buf).strip()
        if body:
            sections.append((cur_title or "正文", body))
        cur_title, cur_buf = None, []

    for ln in lines:
        ln_stripped = ln.strip()
        m_hex = RE_HEX_SECTION.match(ln_stripped)
        if m_hex:
            flush()
            cur_title = "0x" + re.findall(r"0x[0-9A-Fa-f]{2,}", ln_stripped)[0] + " " + m_hex.group(1)
            continue
        if any(ln_stripped.startswith(h) for h in CN_HEADINGS) and len(ln_stripped) <= 32:
            flush()
            cur_title = ln_stripped
            continue
        if (RE_SHORT_CN_TITLE.match(ln_stripped) or re.match(r"^\s*\d{1,2}[\.、]\s*\S.+$", ln_stripped)) and len(ln_stripped) <= 32:
            flush()
            cur_title = ln_stripped
            continue
        cur_buf.append(ln)

    flush()
    return [(t, b) for t, b in sections if b and len(b) > 50]

def chunk_paragraph(text: str, max_chars: int, overlap: int) -> List[str]:
    text = text.strip()
    if not text:
        return []
    if len(text) <= max_chars:
        return [text]
    # 先按句子滑窗
    parts = sliding_window(split_sentences(text), max_chars, overlap)
    # 若仍有任意块 > max_chars（极罕见），再硬切一次兜底
    final = []
    for p in parts:
        if len(p) > max_chars:
            final.extend(_hard_slice(p, max_chars, overlap))
        else:
            final.append(p)
    return final

# -------- I/O 与编码处理 --------
def _decode_with_candidates(data: bytes, prefer: str, verbose=False) -> Tuple[str, str]:
    """根据 BOM 和候选编码尝试解码，返回 (text, encoding)。"""
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
    # 常见中文场景候选
    candidates.extend([
        "utf-8",  # 无 BOM 的 UTF-8
        locale.getpreferredencoding(False) or "cp936",
        "gb18030", "gbk",
        "utf-16", "utf-16-le", "utf-16-be",
    ])
    # 去重，保持顺序
    seen = set(); ordered = []
    for enc in candidates:
        e = enc.lower()
        if e not in seen:
            ordered.append(e); seen.add(e)

    last_err = None
    for enc in ordered:
        try:
            txt = data.decode(enc)
            return txt, enc
        except Exception as e:
            last_err = e
            continue
    # 兜底（不会抛异常，但会替换未知字符）
    try:
        return data.decode("utf-8", errors="replace"), "utf-8(replace)"
    except Exception:
        # 最后再强退成本地编码
        return data.decode(locale.getpreferredencoding(False) or "cp936", errors="replace"), "locale(replace)"

def read_text_file(path: str, prefer_encoding: str = "auto", verbose=False) -> Tuple[str, str]:
    """一次性读取并自动识别编码。"""
    with open(path, "rb") as f:
        data = f.read()
    text, enc = _decode_with_candidates(data, prefer=prefer_encoding, verbose=verbose)
    return text, enc

def collect_files(data_dir: str) -> List[str]:
    pats = [os.path.join(data_dir, "**", "*.txt"), os.path.join(data_dir, "**", "*.md")]
    paths: List[str] = []
    for p in pats:
        paths.extend(glob.glob(p, recursive=True))
    paths = [p for p in sorted(set(paths)) if os.path.isfile(p)]
    return paths

# -------- 主流程 --------
def stage_time(start):
    return f"{(time.perf_counter()-start)*1000:.0f}ms"

def choose_and_chunk(raw: str, title: str, max_chars: int, overlap: int) -> List[Dict[str, Any]]:
    raw = clean_text(normalize_functions(raw))
    secs = detect_sections(raw)
    chunks: List[Dict[str, Any]] = []

    if secs:
        for i, (sec_title, body) in enumerate(secs):
            body_wo_fence = RE_CODE_FENCE.sub(" [代码示例略] ", body)
            parts = chunk_paragraph(body_wo_fence, max_chars, overlap)
            for k, piece in enumerate(parts):
                content = f"【文档】{title}\n【节】{sec_title}\n{piece.strip()}"
                meta = {"title": title, "section": sec_title, "idx_in_section": k}
                chunks.append({"content": content, "metadata": meta})
        return chunks

    body_wo_fence = RE_CODE_FENCE.sub(" [代码示例略] ", raw)
    parts = chunk_paragraph(body_wo_fence, max_chars, overlap)
    for i, piece in enumerate(parts):
        content = f"【文档】{title}\n{piece.strip()}"
        meta = {"title": title, "idx": i}
        chunks.append({"content": content, "metadata": meta})
    return chunks

def main():
    ap = argparse.ArgumentParser(description="读取 data 目录中文语料，清洗/切分并上传（编码自动识别 + 详细进度与耗时诊断）")
    ap.add_argument("--db", required=True, help="数据库名，如 student_Group10_corpus")
    ap.add_argument("--data-dir", default="data", help="语料目录（默认 data）")
    ap.add_argument("--max-chars", type=int, default=700, help="chunk 最大字符数（推荐 500–800）")
    ap.add_argument("--overlap", type=int, default=120, help="chunk 滑窗重叠字符数")
    ap.add_argument("--recreate", action="store_true", help="上传前清空库")
    ap.add_argument("--batch-size", type=int, default=50, help="上传批次大小")
    ap.add_argument("--preview", type=int, default=8, help="打印前 N 个构建的 chunk 预览")
    ap.add_argument("--max-files", type=int, default=0, help="仅处理前 N 个文件（0 表示全部）")
    ap.add_argument("--dry-run", action="store_true", help="仅构建不上传（用于定位慢在切分还是上传）")
    ap.add_argument("--verbose", action="store_true", help="打印 DEBUG 日志")
    ap.add_argument("--encoding", default="auto", help="文件编码：auto/utf-8/gbk/gb18030/utf-16 等，默认 auto")
    args = ap.parse_args()

    s = Settings()
    api = APIClient(base_url=s.base_url, timeout=s.timeout)
    token = token_for_db(args.db, s)

    log(f"运行参数: db={args.db}, data_dir={args.data_dir}, max_chars={args.max_chars}, overlap={args.overlap}, batch={args.batch_size}, recreate={args.recreate}, dry_run={args.dry_run}, preview={args.preview}, max_files={args.max_files}, encoding={args.encoding}", "INFO")
    log(f"环境: pkg={PKG_NAME}, base_url={s.base_url}, timeout={s.timeout}s, locale={locale.getpreferredencoding(False)}", "INFO")
    if os.name == "nt":
        log("检测到 Windows 环境：若 PowerShell 中使用 type 显示乱码，可改用 Get-Content -Encoding UTF8。CMD 可先执行 chcp 65001。", "INFO")

    t0 = time.perf_counter()
    paths = collect_files(args.data_dir)
    if args.max_files and len(paths) > args.max_files:
        paths = paths[:args.max_files]
    if not paths:
        print(json.dumps({"ok": False, "message": f"未在 {args.data_dir} 下找到 .txt/.md 文件"}, ensure_ascii=False))
        return
    log(f"发现文件: {len(paths)} 个", "INFO")
    for p in paths[:10]:
        log(f"  - {p}", "DEBUG", verbose=args.verbose)

    # 读取 + 切分
    t_read = time.perf_counter()
    all_payload: List[Dict[str, Any]] = []
    total_chars = 0
    per_file_stats = []
    for idx, pth in enumerate(paths, 1):
        t_file = time.perf_counter()
        try:
            raw, enc = read_text_file(pth, prefer_encoding=args.encoding, verbose=args.verbose)
        except Exception as e:
            log(f"[{idx}/{len(paths)}] 读取异常：{pth} -> {e}", "ERROR", force=True)
            continue
        read_ms = (time.perf_counter() - t_file) * 1000
        total_chars += len(raw)
        title = os.path.splitext(os.path.basename(pth))[0]

        t_ck = time.perf_counter()
        chunks = choose_and_chunk(raw, title=title, max_chars=args.max_chars, overlap=args.overlap)
        ck_ms = (time.perf_counter() - t_ck) * 1000

        for ch in chunks:
            text = ch["content"]
            meta = ch["metadata"] or {}
            meta.update({"source": pth, "encoding": enc})
            kws = shortlist_keywords(text)
            if kws:
                meta["keywords"] = kws
            all_payload.append({"file": text, "metadata": meta})

        per_file_stats.append({
            "path": pth,
            "encoding": enc,
            "chars": len(raw),
            "chunks": len(chunks),
            "t_read_ms": round(read_ms),
            "t_chunk_ms": round(ck_ms),
        })
        log(f"[{idx}/{len(paths)}] 读取{round(read_ms)}ms 切分{round(ck_ms)}ms - {os.path.basename(pth)} (enc={enc}, chars={human(len(raw))}, chunks={len(chunks)})", "INFO")

    read_ck_cost = stage_time(t_read)
    log(f"读取+切分完成: 文件={len(paths)}，总字符≈{human(total_chars)}，总chunk={len(all_payload)}，耗时={read_ck_cost}", "INFO")

    # 预览
    for i, it in enumerate(all_payload[:max(0, min(args.preview, len(all_payload)))]):
        log(f"--- 预览 chunk #{i} ---", "DEBUG", verbose=args.verbose)
        if args.verbose:
            print(it["file"][:500] + ("..." if len(it["file"]) > 500 else ""))
            print("metadata:", it["metadata"])

    if args.dry_run:
        log("dry-run 模式：不执行上传。若此阶段很快，说明慢点在“上传/向量化/API”。", "INFO")
        print(json.dumps({
            "ok": True,
            "dry_run": True,
            "files": len(paths),
            "total_chars": total_chars,
            "total_chunks": len(all_payload),
            "read_chunk_time": read_ck_cost,
            "preview": min(args.preview, len(all_payload)),
            "per_file_stats": per_file_stats[:10],
        }, ensure_ascii=False, indent=2))
        return

    # 清空库（如指定）
    if args.recreate:
        log("准备清空目标库中的旧文件...", "INFO")
        t_del = time.perf_counter()
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
            t_one = time.perf_counter()
            try:
                api.delete_file(args.db, fid, token)
                del_cnt += 1
            except Exception as e:
                log(f"删除 file_id={fid} 失败：{e}", "ERROR", force=True)
            else:
                dt = (time.perf_counter() - t_one) * 1000
                if dt > 1500:
                    log(f"删除耗时较长：{round(dt)}ms (file_id={fid})", "WARN")
        log(f"清空完成：删除 {del_cnt} 条，耗时={stage_time(t_del)}", "INFO")

    # 上传
    log(f"开始上传：总chunk={len(all_payload)}，batch={args.batch_size}", "INFO")
    t_up = time.perf_counter()
    batch, B = [], args.batch_size
    total_batches = (len(all_payload) + B - 1) // B
    uploaded = 0
    slow_batches = 0

    for i, it in enumerate(all_payload, 1):
        batch.append(it)
        if len(batch) >= B:
            cur_batch_no = (uploaded // B) + 1
            log(f"↑ 上传批次 {cur_batch_no}/{total_batches}（size={len(batch)}）…", "INFO")
            t_b = time.perf_counter()
            try:
                api.upload_files(args.db, batch, token)
            except Exception as e:
                log(f"批次 {cur_batch_no} 上传失败：{e}", "ERROR", force=True)
                # 保留失败批次样本帮助排查
                sample = batch[0]
                log(f"失败样本 metadata: {json.dumps(sample.get('metadata', {}), ensure_ascii=False)}", "DEBUG", verbose=args.verbose)
                return
            dt_ms = (time.perf_counter() - t_b) * 1000
            uploaded += len(batch)
            spd = len(batch) / max(dt_ms/1000.0, 1e-3)
            lvl = "INFO"
            if dt_ms > 3000:  # 超过 3s 视为慢批
                lvl = "WARN"; slow_batches += 1
            log(f"✓ 批次 {cur_batch_no} 完成，用时={round(dt_ms)}ms，吞吐={spd:.1f} items/s（累计 {uploaded}/{len(all_payload)}）", lvl)
            batch = []

    if batch:
        cur_batch_no = (uploaded // B) + 1
        log(f"↑ 上传批次 {cur_batch_no}/{total_batches}（size={len(batch)}）…", "INFO")
        t_b = time.perf_counter()
        try:
            api.upload_files(args.db, batch, token)
        except Exception as e:
            log(f"批次 {cur_batch_no} 上传失败：{e}", "ERROR", force=True)
            return
        dt_ms = (time.perf_counter() - t_b) * 1000
        uploaded += len(batch)
        spd = len(batch) / max(dt_ms/1000.0, 1e-3)
        lvl = "INFO"
        if dt_ms > 3000:
            lvl = "WARN"; slow_batches += 1
        log(f"✓ 批次 {cur_batch_no} 完成，用时={round(dt_ms)}ms，吞吐={spd:.1f} items/s（累计 {uploaded}/{len(all_payload)}）", lvl)

    upload_cost = stage_time(t_up)
    total_cost = stage_time(t0)
    log(f"上传完成：slow_batches={slow_batches}/{total_batches}，upload_time={upload_cost}，total_time={total_cost}", "INFO")

    # 收尾/抽样
    t_list = time.perf_counter()
    try:
        resp = api.get_files(args.db, token, offset=0, limit=10)
        log(f"列出前 10 条完成，用时={stage_time(t_list)}", "DEBUG", verbose=args.verbose)
        print(json.dumps(resp, ensure_ascii=False, indent=2))
    except Exception as e:
        log(f"列出文件失败：{e}", "ERROR", force=True)

    print(json.dumps({
        "ok": True,
        "uploaded_total": len(all_payload),
        "files": len(paths),
        "total_chars": total_chars,
        "slow_batches": slow_batches,
        "timing": {
            "read_and_chunk": read_ck_cost,
            "upload": upload_cost,
            "total": total_cost
        },
        "per_file_stats": per_file_stats[:10],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
