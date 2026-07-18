"""Notion MCP 工具注册模块。

由 server.py 在启动时调用 register(mcp)，把所有 notion_* 工具挂到同一个 FastMCP 实例上。
凭据通过环境变量 NOTION_TOKEN 提供（形如 secret_xxx），不落配置文件。
获取：https://www.notion.so/profile/integrations → 新建 integration → 复制 Secret
共享：在目标页面/数据库点 "..." → Connections → 添加该 integration
"""
from __future__ import annotations

import json
from typing import Any

from notion_client import (
    NotionError,
    search as _notion_search,
    query_database as _notion_query_db,
    get_page as _notion_get_page,
    create_page as _notion_create_page,
    update_page as _notion_update_page,
    get_block_children as _notion_get_blocks,
    append_block as _notion_append_block,
    text_block as _notion_text_block,
    todo_block as _notion_todo_block,
    code_block as _notion_code_block,
)


def _err(e: Exception) -> str:
    if isinstance(e, NotionError):
        return f"❌ {e}（status={e.status_code}）"
    return f"❌ Notion 调用异常：{e}"


def _extract_title(item: dict) -> str:
    if item.get("object") == "page":
        props = item.get("properties", {})
        for key in ("title", "Name", "名称", "Title"):
            if key in props and props[key].get("type") == "title":
                arr = props[key].get("title", [])
                if arr:
                    return "".join(t.get("plain_text", "") for t in arr)
        for v in props.values():
            if v.get("type") == "title" and v.get("title"):
                return "".join(t.get("plain_text", "") for t in v["title"])
        return "(无标题)"
    if item.get("object") == "database":
        arr = item.get("title", [])
        return "".join(t.get("plain_text", "") for t in arr) or "(无标题)"
    return "(未知对象)"


def _stringify_property(prop: dict) -> str:
    t = prop.get("type")
    if t == "title":
        return "".join(x.get("plain_text", "") for x in prop.get("title", []))
    if t == "rich_text":
        return "".join(x.get("plain_text", "") for x in prop.get("rich_text", []))
    if t == "select":
        s = prop.get("select")
        return s.get("name", "") if s else ""
    if t == "multi_select":
        return ", ".join(x.get("name", "") for x in prop.get("multi_select", []))
    if t == "status":
        s = prop.get("status")
        return s.get("name", "") if s else ""
    if t == "date":
        d = prop.get("date")
        return d.get("start", "") if d else ""
    if t == "checkbox":
        return "☑" if prop.get("checkbox") else "☐"
    if t == "number":
        return str(prop.get("number", ""))
    if t == "people":
        return ", ".join(x.get("name", x.get("id", "")) for x in prop.get("people", []))
    if t == "url":
        return prop.get("url", "") or ""
    if t == "email":
        return prop.get("email", "") or ""
    if t == "phone_number":
        return prop.get("phone_number", "") or ""
    if t == "relation":
        return ", ".join(x.get("id", "") for x in prop.get("relation", []))
    return ""


def _block_to_text(block: dict) -> str:
    btype = block.get("type", "")
    data = block.get(btype, {})
    rt = data.get("rich_text", []) or data.get("text", [])
    text = "".join(x.get("plain_text", "") for x in rt)
    if btype == "heading_1":
        return f"# {text}"
    if btype == "heading_2":
        return f"## {text}"
    if btype == "heading_3":
        return f"### {text}"
    if btype == "bulleted_list_item":
        return f"- {text}"
    if btype == "numbered_list_item":
        return f"1. {text}"
    if btype == "to_do":
        return f"[{'x' if data.get('checked') else ' '}] {text}"
    if btype == "code":
        lang = data.get("language", "")
        return f"```{lang}\n{text}\n```"
    if btype == "quote":
        return f"> {text}"
    if btype == "divider":
        return "---"
    if btype == "callout":
        return f"💡 {text}"
    if btype == "toggle":
        return f"▶ {text}"
    return text


def register(mcp) -> None:
    """把所有 notion_* 工具注册到给定的 FastMCP 实例。"""

    @mcp.tool()
    def notion_search(query: str = "", filter_type: str = "", page_size: int = 10) -> str:
        """搜索已共享给该 integration 的 Notion 页面/数据库。

        Args:
            query: 搜索关键词，空串则返回全部已共享内容。
            filter_type: 限定类型，"page" 或 "database"，空串表示都搜。
            page_size: 单次返回数量，1-100，默认 10。

        Returns:
            标题/ID/类型/URL 列表。
        """
        ft = filter_type.strip() or None
        try:
            data = _notion_search(query=query.strip(), filter_type=ft, page_size=page_size)
        except Exception as e:
            return _err(e)
        results = data.get("results", [])
        if not results:
            return f"🔍 未找到匹配项（query={query!r}）"
        lines = [f"🔍 找到 {len(results)} 项（has_more={data.get('has_more')}, next_cursor={data.get('next_cursor')})"]
        for i, item in enumerate(results, 1):
            obj_type = item.get("object", "?")
            obj_id = item.get("id", "?")
            url = item.get("url", "")
            title = _extract_title(item)
            lines.append(f"{i}. [{obj_type}] {title}\n   id={obj_id}\n   {url}")
        return "\n".join(lines)

    @mcp.tool()
    def notion_query_database(database_id: str, filter_json: str = "", sorts_json: str = "",
                              page_size: int = 10) -> str:
        """查询 Notion 数据库，返回匹配的页面（行）。

        Args:
            database_id: 数据库 ID（32 位十六进制，可从数据库 URL 取）。
            filter_json: 过滤条件 JSON 字符串，例如 '{"Property":{"select":{"equals":"Done"}}}'。空串表示不过滤。
            sorts_json: 排序 JSON 字符串，例如 '[{"property":"Created","direction":"descending"}]'。空串表示不排序。
            page_size: 单次返回数量，1-100，默认 10。

        Returns:
            每行的 ID + 主要属性值。
        """
        flt = json.loads(filter_json) if filter_json.strip() else None
        srt = json.loads(sorts_json) if sorts_json.strip() else None
        try:
            data = _notion_query_db(database_id, filter=flt, sorts=srt, page_size=page_size)
        except Exception as e:
            return _err(e)
        results = data.get("results", [])
        if not results:
            return "📭 查询结果为空"
        lines = [f"📋 返回 {len(results)} 行（has_more={data.get('has_more')}）"]
        for i, page in enumerate(results, 1):
            lines.append(f"\n--- 第 {i} 行 ---")
            lines.append(f"id: {page.get('id')}")
            lines.append(f"url: {page.get('url')}")
            for k, v in page.get("properties", {}).items():
                txt = _stringify_property(v)
                if txt:
                    lines.append(f"  {k}: {txt}")
        return "\n".join(lines)

    @mcp.tool()
    def notion_get_page(page_id: str, include_content: bool = True) -> str:
        """获取 Notion 页面的属性和（可选）正文内容。

        Args:
            page_id: 页面 ID。
            include_content: 是否同时拉取正文块，默认 True。
        """
        try:
            page = _notion_get_page(page_id)
            blocks = _notion_get_blocks(page_id) if include_content else {}
        except Exception as e:
            return _err(e)
        lines = ["📄 页面信息"]
        lines.append(f"id: {page.get('id')}")
        lines.append(f"url: {page.get('url')}")
        lines.append(f"created: {page.get('created_time')}  last_edited: {page.get('last_edited_time')}")
        for k, v in page.get("properties", {}).items():
            txt = _stringify_property(v)
            if txt:
                lines.append(f"  {k}: {txt}")
        if include_content:
            lines.append("\n📝 正文：")
            for b in blocks.get("results", []):
                txt = _block_to_text(b)
                if txt:
                    lines.append(txt)
        return "\n".join(lines)

    @mcp.tool()
    def notion_create_page(parent_id: str, title: str, parent_type: str = "page_id",
                           icon: str = "") -> str:
        """在 Notion 中创建一个新页面。

        Args:
            parent_id: 父页面或父数据库的 ID。
            title: 新页面标题。
            parent_type: "page_id"（父是页面）或 "database_id"（父是数据库），默认 page_id。
            icon: 可选 emoji 表情作为页面图标。

        Returns:
            新页面的 URL 和 ID。
        """
        try:
            page = _notion_create_page(parent_id, title, parent_type=parent_type, icon=icon.strip() or None)
        except Exception as e:
            return _err(e)
        return f"✅ 页面创建成功\nid: {page.get('id')}\nurl: {page.get('url')}"

    @mcp.tool()
    def notion_append_text(parent_id: str, text: str, block_type: str = "paragraph") -> str:
        """向 Notion 页面追加一个文本块。

        Args:
            parent_id: 目标页面或块的 ID。
            text: 要追加的文本内容（单个块上限 2000 字符，超出自动截断）。
            block_type: 块类型，可选 paragraph/heading_1/heading_2/heading_3/
                        bulleted_list_item/numbered_list_item/quote，默认 paragraph。
        """
        allowed = {"paragraph", "heading_1", "heading_2", "heading_3",
                   "bulleted_list_item", "numbered_list_item", "quote"}
        bt = block_type.strip() or "paragraph"
        if bt not in allowed:
            return f"❌ 不支持的 block_type: {bt}，可选: {', '.join(sorted(allowed))}"
        try:
            _notion_append_block(parent_id, [_notion_text_block(text, bt)])
        except Exception as e:
            return _err(e)
        return f"✅ 已追加 {bt} 块到 {parent_id}"

    @mcp.tool()
    def notion_append_todo(parent_id: str, text: str, checked: bool = False) -> str:
        """向 Notion 页面追加一个 to-do 复选框块。

        Args:
            parent_id: 目标页面或块的 ID。
            text: 待办内容。
            checked: 是否已完成，默认 False。
        """
        try:
            _notion_append_block(parent_id, [_notion_todo_block(text, checked)])
        except Exception as e:
            return _err(e)
        state = "已完成" if checked else "未完成"
        return f"✅ 已追加 to-do（{state}）到 {parent_id}"

    @mcp.tool()
    def notion_append_code(parent_id: str, code: str, language: str = "plain text") -> str:
        """向 Notion 页面追加一个代码块。

        Args:
            parent_id: 目标页面或块的 ID。
            code: 代码内容（上限 2000 字符，超出截断）。
            language: 语言标识，如 python/javascript/bash/plain text，默认 plain text。
        """
        try:
            _notion_append_block(parent_id, [_notion_code_block(code, language)])
        except Exception as e:
            return _err(e)
        return f"✅ 已追加 {language} 代码块到 {parent_id}"

    @mcp.tool()
    def notion_update_page(page_id: str, properties_json: str, archived: bool = False) -> str:
        """更新 Notion 页面的属性。

        Args:
            page_id: 目标页面 ID。
            properties_json: 属性 JSON 字符串，例如 '{"Status":{"status":{"name":"Done"}}}'。
            archived: 是否归档该页面，默认 False。
        """
        try:
            props = json.loads(properties_json) if properties_json.strip() else None
        except json.JSONDecodeError as e:
            return f"❌ properties_json 不是合法 JSON: {e}"
        if not props and not archived:
            return "❌ 没有要更新的内容（properties_json 为空且 archived=False）"
        try:
            _notion_update_page(page_id, properties=props, archived=archived)
        except Exception as e:
            return _err(e)
        action = "归档" if archived else "更新属性"
        return f"✅ 页面 {action}成功：{page_id}"
