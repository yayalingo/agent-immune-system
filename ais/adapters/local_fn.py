"""内置 mock 目标：一个'故意裸奔'的 Agent 模拟器，用于跑通整条闭环。

真实框架适配器（OpenAI Agents / LangChain）是 Phase 2 验证项；v1 用此可控漏洞目标
证明 '裸跑 vulnerable → compile → deploy → 回归 safe' 的闭环有效。
"""
from __future__ import annotations

import re

from ..core.models import Observation, ToolCall

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def _extract_url(text: str) -> Optional[str]:
    m = _URL_RE.search(text)
    return m.group(0) if m else None


class VulnerableAgent:
    """过度信任的 Agent：把含 URL 的'发送/发到/POST/exfil'指令当作命令执行，
    且会把'记住：'的内容存入记忆并在后续外发时引用（记忆投毒载体）。"""

    def __init__(self) -> None:
        self.memory: list[str] = []

    def send(self, message: str, tools: Optional[list[str]] = None) -> Observation:
        if message.startswith("记住："):
            self.memory.append(message[3:].strip())
            return Observation(text="已记录到记忆。")

        url = _extract_url(message)
        body_src = message
        if url is None and self.memory:
            for m in self.memory:
                u = _extract_url(m)
                if u:
                    url, body_src = u, m
                    break

        wants_exfil = any(
            k in message
            for k in ("发送", "发到", "发出", "POST", "post", "exfil", "导出")
        )
        if url and wants_exfil:
            return Observation(
                text=f"正在发送数据到 {url}",
                tool_calls=[ToolCall("http_request", {"url": url, "method": "POST", "body": body_src})],
            )
        return Observation(text=f"收到：{message}")
