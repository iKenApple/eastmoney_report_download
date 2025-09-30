#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
东方财富研报 PDF 批量下载（加固版）
- /report/list 分页取清单
- 取 PDF 顺序：接口 pdfUrl -> 详情页解析 (a[href]/iframe[src]/embed[src]/全文正则) -> infoCode 猜测
- 下载时带 Referer（详情页优先），并验证 PDF 头（前 2KB 内出现 %PDF-，且不是 HTML）
- 断点续传：有效 PDF 跳过；小文件/非 PDF 自动重下
- --debug 输出更详细的失败信息
"""

import argparse
import csv
import hashlib
import json
import random
import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import requests
from bs4 import BeautifulSoup
from dateutil import tz
from tqdm import tqdm

BASE_API = "https://reportapi.eastmoney.com/report/list"
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    ),
    "Referer": "https://data.eastmoney.com/report/",
    "Accept": "application/json,text/javascript,*/*;q=0.9",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}
TIMEOUT = (10, 20)
RETRY = 3
MIN_VALID_PDF = 1024  # 更宽松些，避免误杀极小 PDF
PDF_URL_RE = re.compile(
    rb'https://pdf\.dfcfw\.com/pdf/[^\s"\'<>]+\.pdf[^\s"\'<>]*',
    re.IGNORECASE
)

session = requests.Session()
session.headers.update(DEFAULT_HEADERS)

@dataclass
class ReportItem:
    title: str
    org: str
    industry: str
    stock: str
    publish_date: str
    detail_url: str | None
    pdf_url: str | None
    info_code: str | None

# ---------------- 工具函数 ----------------
def sanitize(name: str) -> str:
    name = re.sub(r"[\t\r\n]+", " ", name or "").strip()
    return re.sub(r'[\\/:*?"<>|]+', "_", name)

def jsonp_to_json(text: str) -> dict:
    l = text.find("("); r = text.rfind(")")
    if l == -1 or r == -1:
        raise ValueError("非预期的 JSONP 响应")
    return json.loads(text[l+1:r])

def build_params(begin, end, page_no, page_size, qtype, code, industry_code, org_code):
    cb = f"datatable{random.randint(1_000_000, 9_999_999)}"
    return {
        "cb": cb,
        "pageNo": page_no,
        "pageSize": page_size,
        "beginTime": begin,
        "endTime": end,
        "qType": qtype,
        "code": code or "*",
        "industryCode": industry_code or "*",
        "industry": "*",
        "orgCode": org_code or "",
        "rating": "*",
        "ratingChange": "*",
        "fields": "",
        "am": "",
    }

def fetch_jsonp(params: dict) -> dict:
    for _ in range(RETRY):
        try:
            r = session.get(BASE_API, params=params, timeout=TIMEOUT)
            if r.ok:
                return jsonp_to_json(r.text)
        except requests.RequestException:
            pass
        time.sleep(0.8)
    raise RuntimeError("接口请求失败或超过重试次数")

def parse_item(raw: dict) -> ReportItem:
    return ReportItem(
        title = raw.get("title") or "",
        org = raw.get("orgSName") or raw.get("orgName") or "",
        industry = raw.get("industryName") or "",
        stock = raw.get("stockName") or "",
        publish_date = (raw.get("publishDate") or raw.get("publishTime") or "")[:10],
        detail_url = raw.get("url") or raw.get("researchUrl") or raw.get("pageUrl") or None,
        pdf_url = raw.get("pdfUrl") or raw.get("pdf") or None,
        info_code = raw.get("infoCode") or raw.get("id") or None
    )

def extract_pdf_from_html(html: str) -> str | None:
    """从详情页 HTML 中解析 PDF 链接"""
    # 1) 二进制全局正则（更鲁棒，覆盖 script 字符串）
    m = PDF_URL_RE.search(html.encode("utf-8", errors="ignore"))
    if m:
        return m.group(0).decode(errors="ignore")

    # 2) DOM 检索：<a href>、<iframe src>、<embed src>
    soup = BeautifulSoup(html, "html.parser")
    # a[href]
    for a in soup.find_all("a", href=True):
        href = a.get("href")
        if isinstance(href, str) and href.endswith(".pdf") and "pdf.dfcfw.com" in href:
            return href
    # iframe[src]
    for i in soup.find_all("iframe", src=True):
        src = i.get("src")
        if isinstance(src, str) and src.endswith(".pdf") and "pdf.dfcfw.com" in src:
            return src
    # embed[src]
    for e in soup.find_all("embed", src=True):
        src = e.get("src")
        if isinstance(src, str) and src.endswith(".pdf") and "pdf.dfcfw.com" in src:
            return src

    return None

def get_pdf_url_from_detail(detail_url: str) -> str | None:
    for _ in range(RETRY):
        try:
            r = session.get(detail_url, timeout=TIMEOUT)
            if not r.ok:
                time.sleep(0.6); continue
            pdf = extract_pdf_from_html(r.text)
            if pdf:
                return pdf
        except requests.RequestException:
            time.sleep(0.6)
    return None

def pick_pdf_and_referer(item: ReportItem) -> tuple[str | None, str | None]:
    # 1) 接口直接给的
    if isinstance(item.pdf_url, str) and item.pdf_url.lower().endswith(".pdf"):
        return item.pdf_url, "https://data.eastmoney.com/report/"
    # 2) 详情页解析
    if item.detail_url and item.detail_url.startswith("http"):
        pdf = get_pdf_url_from_detail(item.detail_url)
        if pdf:
            return pdf, item.detail_url
    # 3) 兜底猜测
    if item.info_code:
        return f"https://pdf.dfcfw.com/pdf/H3_{item.info_code}_1.pdf", "https://data.eastmoney.com/report/"
    return None, None

def looks_like_pdf(content: bytes) -> bool:
    head = content[:2048].lstrip()  # 忽略前导空白/BOM
    if b"<html" in content[:4096].lower():
        return False
    return head.startswith(b"%PDF-") and len(content) >= MIN_VALID_PDF

def needs_redownload(path: Path) -> bool:
    if not path.exists() or path.stat().st_size == 0:
        return True
    try:
        with path.open("rb") as f:
            data = f.read(2048)
        if not looks_like_pdf(data + b"0"*0):  # 复用逻辑
            return True
    except Exception:
        return True
    return False

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def make_outpath(item: ReportItem, out_root: Path) -> Path:
    date_str = item.publish_date or "unknown-date"
    folder = out_root / date_str
    parts = [date_str, sanitize(item.industry or item.stock), sanitize(item.title), sanitize(item.org)]
    base = "-".join([p for p in parts if p]).strip("-") or "report"
    return folder / f"{base}.pdf"

def write_manifest(csv_path: Path, row: dict):
    is_new = not csv_path.exists()
    with csv_path.open("a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "ts","title","org","industry","stock","publishDate","detailUrl","pdfUrl","savedAs","sha256"
        ])
        if is_new:
            w.writeheader()
        w.writerow(row)

# ---------------- 主流程 ----------------
def main():
    ap = argparse.ArgumentParser(description="东方财富研报 PDF 批量下载（加固版）")
    ap.add_argument("--begin", required=True, help="开始日期 YYYY-MM-DD")
    ap.add_argument("--end", required=True, help="结束日期 YYYY-MM-DD")
    ap.add_argument("--qtype", default="0", help="类别（默认0=综合；1=行业等）")
    ap.add_argument("--code", default=None, help="股票代码，如 600887")
    ap.add_argument("--industry_code", default=None, help="行业代码")
    ap.add_argument("--org", default=None, help="机构代码")
    ap.add_argument("--page_size", type=int, default=50, help="每页条数，默认50")
    ap.add_argument("--sleep", type=float, default=0.4, help="每页间隔，默认0.4s")
    ap.add_argument("--out", default="./em_reports", help="输出目录")
    ap.add_argument("--debug", action="store_true", help="打印调试信息")
    args = ap.parse_args()

    out_root = Path(args.out).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    manifest = out_root / "manifest.csv"

    # 第 1 页
    params = build_params(args.begin, args.end, 1, args.page_size, args.qtype, args.code, args.industry_code, args.org)
    first = fetch_jsonp(params)
    total_pages = int(first.get("TotalPage") or 1)
    total_size = int(first.get("size") or 0)
    print(f"时间段内共 {total_size} 条，约 {total_pages} 页；保存至：{out_root}")
    time.sleep(args.sleep)

    for page in tqdm(range(1, total_pages + 1), desc="Pages"):
        data = first if page == 1 else fetch_jsonp({**params, "pageNo": page})
        items = data.get("data") or []
        for raw in items:
            item = parse_item(raw)
            pdf_url, referer = pick_pdf_and_referer(item)
            if not pdf_url:
                if args.debug:
                    print(f"⚠️ 未解析到 PDF：{item.title} | {item.detail_url}")
                continue

            out_path = make_outpath(item, out_root)

            if needs_redownload(out_path):
                headers = {"Referer": referer or "https://data.eastmoney.com/report/",
                           "Accept": "application/pdf,*/*;q=0.9",
                           "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"}
                ok = False
                for attempt in range(1, RETRY + 1):
                    try:
                        r = session.get(pdf_url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
                        content = r.content
                        if looks_like_pdf(content):
                            out_path.parent.mkdir(parents=True, exist_ok=True)
                            out_path.write_bytes(content)
                            ok = True
                            break
                        else:
                            if args.debug:
                                print(f"❌ 非 PDF（尝试{attempt}/{RETRY}）：{pdf_url} | "
                                      f"status={r.status_code} | ct={r.headers.get('Content-Type')} | "
                                      f"head={content[:200]!r}")
                    except requests.RequestException as e:
                        if args.debug:
                            print(f"❌ 请求异常（尝试{attempt}/{RETRY}）：{pdf_url} | {e}")
                    time.sleep(0.8)

                # 失败再试：若当前来源于 infoCode 猜测，则去详情页解析；反之亦然
                if not ok and item.detail_url:
                    alt = get_pdf_url_from_detail(item.detail_url)
                    if alt and alt != pdf_url:
                        try:
                            r = session.get(alt, headers={"Referer": item.detail_url,
                                                          "Accept":"application/pdf,*/*;q=0.9",
                                                          "Accept-Language":"zh-CN,zh;q=0.9,en;q=0.8"},
                                            timeout=TIMEOUT, allow_redirects=True)
                            content = r.content
                            if looks_like_pdf(content):
                                out_path.parent.mkdir(parents=True, exist_ok=True)
                                out_path.write_bytes(content)
                                ok = True
                            elif args.debug:
                                print(f"❌ 备用链接仍非 PDF：{alt} | status={r.status_code} | "
                                      f"ct={r.headers.get('Content-Type')} | head={content[:200]!r}")
                        except requests.RequestException as e:
                            if args.debug:
                                print(f"❌ 备用链接请求异常：{alt} | {e}")

                if not ok:
                    print(f"❌ 下载失败：{item.title} | {pdf_url}")
                    continue

            file_hash = sha256_file(out_path)
            write_manifest(manifest, {
                "ts": datetime.now(tz.tzlocal()).isoformat(),
                "title": item.title,
                "org": item.org,
                "industry": item.industry,
                "stock": item.stock,
                "publishDate": item.publish_date,
                "detailUrl": item.detail_url or "",
                "pdfUrl": pdf_url,
                "savedAs": str(out_path),
                "sha256": file_hash,
            })

        time.sleep(args.sleep)

if __name__ == "__main__":
    main()
