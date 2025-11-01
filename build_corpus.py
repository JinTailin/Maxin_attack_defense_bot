
# file: scripts/build_corpus.py
# 用法（在项目根目录运行）：
#   PowerShell:
#     $env:ATTACK_BOT_USER_TOKEN="你的token"
#     $env:ATTACK_BOT_COMMON_DB_TOKEN="token_common"
#     python scripts/build_corpus.py --db yourname_corpus --glob "data/**/*.txt" --max-chars 800 --overlap 120 --batch-size 50
#
#   Linux/Mac:
#     export ATTACK_BOT_USER_TOKEN="你的token"
#     export ATTACK_BOT_COMMON_DB_TOKEN="token_common"
#     python scripts/build_corpus.py --db yourname_corpus --glob 'data/**/*.md' --max-chars 800 --overlap 120
#
# 说明：
# - 默认只处理 .txt/.md；若安装了 docx2txt 和 pdfplumber，会尝试解析 .docx/.pdf
# - 会自动创建数据库（已存在则忽略错误继续）
# - 按 batch-size 分批上传，附带 metadata 便于后续排查与引用展示

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# 从包内导入配置与 API 客户端
# 注意：需在项目根目录运行（包含 attack_defense_bot 目录）
from attack_defense_bot.config import Settings, token_for_db
from attack_defense_bot.api_client import APIClient


# ---------------- I/O 辅助 ----------------
def read_text_file(p: Path) -> str:
    # 简单的编码回退策略
    for enc in ("utf-8", "utf-8-sig", "gb18030", "latin-1"):
        try:
            return p.read_text(encoding=enc)
        except Exception:
            continue
    raise RuntimeError(f"无法以常见编码读取文件: {p}")


def try_read_docx(p: Path) -> Optional[str]:
    try:
        import docx2txt  # type: ignore
    except Exception:
        return None
    try:
        return docx2txt.process(str(p))
    except Exception:
        return None


def try_read_pdf(p: Path) -> Optional[str]:
    try:
        import pdfplumber  # type: ignore
    except Exception:
        return None
    try:
        text_parts: List[str] = []
        with pdfplumber.open(str(p)) as pdf:
            for page in pdf.pages:
                text_parts.append(page.extract_text() or "")
        return "\n".join(text_parts).strip()
    except Exception:
        return None


def load_document(p: Path) -> Optional[str]:
    ext = p.suffix.lower()
    if ext in [".txt", ".md"]:
        return read_text_file(p)
    if ext == ".docx":
        return try_read_docx(p)
    if ext == ".pdf":
        return try_read_pdf(p)
    return None


# ---------------- 文本处理与分块 ----------------
_SENT_SPLIT_RE = re.compile(r"(?<=[。！!？?；;：:\.\!\?\n])\s*")

def clean_text(text: str) -> str:
    # 基本清洗：标准化空白、去 BOM、去重复空行
    text = text.replace("\ufeff", "")
    text = re.sub(r"\r\n?", "\n", text)
    # 合并 3 个以上的空行为 2 个
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def split_sentences(text: str) -> List[str]:
    # 粗略句子切分，保留标点，有助于分块后的可读性
    parts = [s.strip() for s in _SENT_SPLIT_RE.split(text) if s.strip()]
    return parts


def sliding_window(sentences: List[str], max_chars: int, overlap: int) -> List[str]:
    chunks: List[str] = []
    current: List[str] = []
    current_len = 0

    for s in sentences:
        slen = len(s)
        if current_len + slen + 1 <= max_chars or not current:
            current.append(s)
            current_len += slen + 1
        else:
            # 输出一个 chunk
            chunks.append("".join(current).strip())
            # 构造重叠窗口
            if overlap > 0 and chunks[-1]:
                # 从当前 chunk 末尾回退 overlap 字符开始
                tail = chunks[-1][-overlap:]
                # 在 sentences 中重新起一个窗口：用 tail 作为开头
                current = [tail, s]
                current_len = len(tail) + len(s) + 1
            else:
                current = [s]
                current_len = slen + 1

    if current:
        chunks.append("".join(current).strip())

    # 再次截断过长的末尾（极少数长句导致）
    chunks = [c[:max_chars] for c in chunks if c]
    return chunks


def chunk_text(text: str, max_chars: int = 800, overlap: int = 120) -> List[str]:
    text = clean_text(text)
    sentences = split_sentences(text)
    if not sentences:
        return []
    return sliding_window(sentences, max_chars=max_chars, overlap=overlap)


# ---------------- 上传流程 ----------------
def build_files_payload(docs: List[Tuple[Path, str]], max_chars: int, overlap: int) -> List[Dict[str, Any]]:
    files: List[Dict[str, Any]] = []
    for path, content in docs:
        chunks = chunk_text(content, max_chars=max_chars, overlap=overlap)
        rel = str(path)
        for i, ch in enumerate(chunks):
            files.append({
                "file": ch,
                "metadata": {
                    "source": rel,
                    "chunk_index": i,
                    "chunk_of": path.name,
                    "ext": path.suffix.lower(),
                }
            })
    return files


def batch(iterable: List[Any], size: int) -> Iterable[List[Any]]:
    for i in range(0, len(iterable), size):
        yield iterable[i:i+size]


def ensure_database(api: APIClient, db_name: str, token: str, metric: str) -> None:
    resp = api.create_database(database_name=db_name, token=token, metric_type=metric)
    # 数据库可能已存在：如果失败但不是权限问题，可以忽略
    status = resp.get("http_status")
    if status != 200:
        # 有些后端会返回 4xx + 已存在/不可重复创建 的提示
        # 这里仅记录日志到 stderr，继续后续流程
        sys.stderr.write(f"[warn] create_database http={status}, data={resp.get('data')}\n")


def upload_corpus(
    db_name: str,
    file_glob: str,
    metric: str,
    max_chars: int,
    overlap: int,
    batch_size: int,
) -> None:
    settings = Settings()
    # RAG 检索 token 依赖库名，但“建库与上传”通常需要授权 token（一般用 user_token）
    # 若你要往 common_dataset 上传，请改用 token_for_db(db_name, settings)
    write_token = settings.user_token

    api = APIClient(base_url=settings.base_url, timeout=settings.timeout)

    # 1) 创建数据库（存在则忽略）
    ensure_database(api, db_name=db_name, token=write_token, metric=metric)

    # 2) 收集文件
    paths = sorted(Path().glob(file_glob))
    if not paths:
        print(f"没有匹配到任何文件：{file_glob}")
        return

    docs: List[Tuple[Path, str]] = []
    for p in paths:
        if not p.is_file():
            continue
        content = load_document(p)
        if not content:
            sys.stderr.write(f"[skip] 不支持的格式或解析失败: {p}\n")
            continue
        if not content.strip():
            sys.stderr.write(f"[skip] 空文件: {p}\n")
            continue
        docs.append((p, content))

    if not docs:
        print("没有可上传的文档内容。")
        return

    # 3) 分块并构建 payload
    files_payload = build_files_payload(docs, max_chars=max_chars, overlap=overlap)
    print(f"准备上传：文档 {len(docs)} 个，chunk {len(files_payload)} 条（batch={batch_size}）")

    # 4) 分批上传
    uploaded = 0
    for idx, part in enumerate(batch(files_payload, batch_size), start=1):
        resp = api.upload_files(database_name=db_name, files=part, token=write_token)
        ok = resp.get("http_status") == 200 and resp.get("data", {}).get("status") == "success"
        if not ok:
            sys.stderr.write(f"[error] 批次 {idx} 上传失败 http={resp.get('http_status')} data={resp.get('data')}\n")
        else:
            uploaded += len(part)
            print(f"批次 {idx} 成功：+{len(part)}，累计 {uploaded}")

    print(f"上传完成：累计 {uploaded} 条 chunk")


# ---------------- CLI ----------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="构建语料库并上传到向量数据库（RAG）")
    parser.add_argument("--db", required=True, help="数据库名，建议 yourname_corpus 或 groupX_corpus")
    parser.add_argument("--glob", required=True, help="文件通配符，如 'data/**/*.txt' 或 'notes/**/*.md'")
    parser.add_argument("--metric", default="COSINE", help="相似度度量（默认 COSINE）")
    parser.add_argument("--max-chars", type=int, default=800, help="每个 chunk 最大字符数")
    parser.add_argument("--overlap", type=int, default=120, help="chunk 重叠字符数")
    parser.add_argument("--batch-size", type=int, default=50, help="上传批次大小")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    # 将 CLI 参数临时写入 Settings 的运行时配置（实例化时读取）
    os.environ["ATTACK_BOT_DEFAULT_DB"] = args.db
    os.environ["ATTACK_BOT_DEFAULT_METRIC"] = args.metric
    upload_corpus(
        db_name=args.db,
        file_glob=args.glob,
        metric=args.metric,
        max_chars=args.max_chars,
        overlap=args.overlap,
        batch_size=args.batch_size,
    )


if __name__ == "__main__":
    main()
