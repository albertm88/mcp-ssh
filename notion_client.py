"""Notion API 客户端封装。

复用 mcp-ssh 的「密钥不落配置」原则：Integration Token 只从环境变量读取。
  - NOTION_TOKEN          必填，形如 secret_xxxxxxxx
  - NOTION_API_VERSION    可选，默认 2022-06-28
  - NOTION_BASE_URL       可选，默认 https://api.notion.com/v1

只依赖标准库（urllib + json），不引入新依赖，保持项目轻量。
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Optional

from logger import get_logger

_log = get_logger()

_BASE_URL = "https://api.notion.com/v1"
_API_VERSION = "2022-06-28"
_TIMEOUT = 30


class NotionError(RuntimeError):
    """Notion API 调用异常，附带 status_code 与服务器返回的 message。"""

    def __init__(self, message: str, status_code: int = 0, payload: Optional[dict] = None):
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload or {}


def _get_token() -> str:
    token = os.environ.get("NOTION_TOKEN", "").strip()
    if not token:
        raise NotionError(
            "未配置 Notion Integration Token。请设置环境变量 NOTION_TOKEN（形如 secret_xxx），"
            "获取方式：https://www.notion.so/profile/integrations 新建 integration 后复制 Internal Integration Secret。",
            status_code=401,
        )
    return token


def _request(method: str, path: str, body: Optional[dict] = None, timeout: int = _TIMEOUT) -> dict:
    """统一发起 Notion API 请求并解析响应。"""
    base = os.environ.get("NOTION_BASE_URL", _BASE_URL).rstrip("/")
    url = f"{base}{path}"
    token = _get_token()
    version = os.environ.get("NOTION_API_VERSION", _API_VERSION)

    headers = {
        "Authorization": f"Bearer {token}",
        "Notion-Version": version,
        "Content-Type": "application/json",
    }
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    _log.info("notion_request", method=method, path=path, has_body=bool(body))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw)
            msg = payload.get("message", raw)
        except Exception:
            payload = {"raw": raw}
            msg = raw or e.reason
        _log.warning("notion_http_error", method=method, path=path, status=e.code, msg=msg[:200])
        raise NotionError(f"Notion API {method} {path} 失败 [{e.code}]: {msg}", status_code=e.code, payload=payload)
    except urllib.error.URLError as e:
        _log.warning("notion_url_error", method=method, path=path, msg=str(e))
        raise NotionError(f"Notion API 网络错误：{e.reason}", status_code=0)


# ---------- 搜索 ----------

def search(query: str = "", filter_type: Optional[str] = None, page_size: int = 10, start_cursor: Optional[str] = None) -> dict:
    """搜索已与该 integration 共享的页面/数据库。

    Args:
        query: 关键词，空串表示返回全部（受权限范围限制）。
        filter_type: "page" 或 "database"，None 表示都搜。
        page_size: 单页返回数量，1-100。
        start_cursor: 分页游标。
    """
    body: dict[str, Any] = {"page_size": min(max(page_size, 1), 100)}
    if query:
        body["query"] = query
    if filter_type:
        body["filter"] = {"property": "object", "value": filter_type}
    if start_cursor:
        body["start_cursor"] = start_cursor
    return _request("POST", "/v1/search", body=body)


# ---------- 数据库 ----------

def query_database(database_id: str, filter: Optional[dict] = None, sorts: Optional[list] = None,
                   page_size: int = 10, start_cursor: Optional[str] = None) -> dict:
    """查询数据库，返回匹配的页面列表。"""
    body: dict[str, Any] = {"page_size": min(max(page_size, 1), 100)}
    if filter:
        body["filter"] = filter
    if sorts:
        body["sorts"] = sorts
    if start_cursor:
        body["start_cursor"] = start_cursor
    return _request("POST", f"/v1/databases/{database_id}/query", body=body)


def get_database(database_id: str) -> dict:
    """获取数据库的 schema（属性定义）。"""
    return _request("GET", f"/v1/databases/{database_id}")


# ---------- 页面 ----------

def get_page(page_id: str) -> dict:
    """获取页面属性（不含正文，正文用 get_block_children）。"""
    return _request("GET", f"/v1/pages/{page_id}")


def create_page(parent_id: str, title: str, parent_type: str = "page_id",
                properties: Optional[dict] = None, icon: Optional[str] = None) -> dict:
    """创建页面。parent_type 为 page_id 或 database_id。

    对于 database_id 父级，title 会写入名为 "Name"/"名称" 的 title 属性；
    对于 page_id 父级，title 写入 title 属性。
    若需更复杂的属性，可通过 properties 覆盖。
    """
    title_prop = {"title": [{"text": {"content": title}}]} if title else {"title": []}
    if properties:
        props = dict(properties)
        # 若用户没显式给 title，自动补
        if "title" not in props and "Name" not in props and "名称" not in props:
            props["title"] = title_prop
    else:
        props = {"title": title_prop}

    body: dict[str, Any] = {
        "parent": {parent_type: parent_id},
        "properties": props,
    }
    if icon:
        body["icon"] = {"type": "emoji", "emoji": icon}
    return _request("POST", "/v1/pages", body=body)


def update_page(page_id: str, properties: Optional[dict] = None, archived: bool = False) -> dict:
    """更新页面属性或归档。"""
    body: dict[str, Any] = {}
    if properties:
        body["properties"] = properties
    body["archived"] = archived
    return _request("PATCH", f"/v1/pages/{page_id}", body=body)


# ---------- 块（页面正文） ----------

def get_block_children(block_id: str, page_size: int = 100, start_cursor: Optional[str] = None) -> dict:
    """获取某个块/页面的子块（即正文内容）。"""
    params = f"?page_size={min(max(page_size, 1), 100)}"
    if start_cursor:
        params += f"&start_cursor={start_cursor}"
    return _request("GET", f"/v1/blocks/{block_id}/children{params}")


def append_block(parent_id: str, blocks: list[dict]) -> dict:
    """向页面/块追加子块。blocks 为 Notion block 对象列表。"""
    body = {"children": blocks}
    return _request("PATCH", f"/v1/blocks/{parent_id}/children", body=body)


# ---------- 便捷：构造常见块 ----------

def text_block(text: str, block_type: str = "paragraph") -> dict:
    """构造一个简单文本块。block_type: paragraph/heading_1/heading_2/heading_3/bulleted_list_item/numbered_list_item/quote。"""
    rich_text = [{"type": "text", "text": {"content": text[:2000]}}]  # Notion 单个 rich_text content 上限 2000
    return {block_type: {"rich_text": rich_text}}


def todo_block(text: str, checked: bool = False) -> dict:
    return {"to_do": {"rich_text": [{"type": "text", "text": {"content": text[:2000]}}], "checked": checked}}


def code_block(text: str, language: str = "plain text") -> dict:
    return {"code": {"rich_text": [{"type": "text", "text": {"content": text[:2000]}}], "language": language}}
