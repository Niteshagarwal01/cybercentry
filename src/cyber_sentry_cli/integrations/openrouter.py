# pyre-unsafe
"""OpenRouter API client."""

from __future__ import annotations

import json
import logging
from typing import Any, Iterator
from urllib.parse import urlparse

import httpx
from rich.console import Console

from cyber_sentry_cli.core.config import Config

console = Console()
logger = logging.getLogger(__name__)


class OpenRouterClient:
    """Sends chat completions to an OpenAI-compatible endpoint such as OpenRouter or Ollama."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.base_url = config.llm_base_url
        self.api_key = config.openrouter_api_key
        self.chat_model = config.chat_model
        self.coding_model = config.coding_model
        self.temperature = config.temperature
        self.max_tokens = config.max_tokens

    @property
    def is_local_endpoint(self) -> bool:
        host = (urlparse(self.base_url).hostname or "").lower()
        return host in {"localhost", "127.0.0.1", "::1"}

    @property
    def headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if not self.is_local_endpoint:
            headers["HTTP-Referer"] = "https://cybersentry.dev"
            headers["X-Title"] = "CyberSentry"
        return headers

    @property
    def request_timeout(self) -> float:
        return 300.0 if self.is_local_endpoint else 60.0

    def chat(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> str:
        """Send a chat completion request and return the assistant's response text."""
        payload: dict[str, Any] = {
            "model": model or self.chat_model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.temperature,
        }
        if max_tokens:
            payload["max_tokens"] = max_tokens

        # Best-effort JSON mode via OpenRouter
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
            # Some OpenRouter models require the word 'JSON' in the system prompt
            if messages and messages[0]["role"] == "system":
                if "json" not in messages[0]["content"].lower():
                    messages[0]["content"] += "\nYou must reply in valid JSON format."

        try:
            with httpx.Client(timeout=self.request_timeout) as client:
                response = client.post(
                    f"{self.base_url}/chat/completions",
                    headers=self.headers,
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
                return data["choices"][0]["message"]["content"]
        except httpx.HTTPError as e:
            msg = f"API Error: {e}"
            if hasattr(e, "response") and e.response is not None:
                try:
                    err_json = e.response.json()
                    err_msg = err_json.get("error", {}).get("message", e.response.text)
                    msg = f"API Error ({e.response.status_code}): {err_msg}"
                except Exception:
                    msg = f"API Error ({e.response.status_code}): {e.response.text}"
            console.print(f"[bold red]{msg}[/]")
            raise RuntimeError(msg)
        except (KeyError, IndexError) as e:
            msg = f"Unexpected API response format: {e}"
            console.print(f"[bold red]{msg}[/]")
            raise RuntimeError(msg)

    def is_configured(self) -> bool:
        """Return True if a usable backend is configured."""
        return self.is_local_endpoint or bool(self.api_key)

    def chat_json(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> dict:
        """Send a chat request in JSON mode and return the parsed dict."""
        response = self.chat(
            messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            json_mode=True,
        )
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            logger.warning("LLM returned invalid JSON in chat_json (len=%d). Response start: %s", len(response), response[:120])
            return {}

    def chat_stream(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float | None = None,
    ) -> Iterator[str]:
        """Stream chat tokens."""
        payload: dict[str, Any] = {
            "model": model or self.chat_model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.temperature,
            "stream": True,
        }

        try:
            with httpx.Client(timeout=self.request_timeout) as client:
                with client.stream(
                    "POST",
                    f"{self.base_url}/chat/completions",
                    headers=self.headers,
                    json=payload,
                ) as response:
                    response.raise_for_status()
                    for line in response.iter_lines():
                        if line.startswith("data: "):
                            data_str = line[6:]
                            if data_str == "[DONE]":
                                break
                            try:
                                data = json.loads(data_str)
                                chunk = data["choices"][0].get("delta", {}).get("content", "")
                                if chunk:
                                    yield chunk
                            except (json.JSONDecodeError, KeyError, IndexError):
                                continue
        except httpx.HTTPError as e:
            msg = f"API Stream Error: {e}"
            if hasattr(e, "response") and e.response is not None:
                msg = f"API Stream Error ({e.response.status_code})"
            console.print(f"\n[bold red]{msg}[/]")
            # Yield sanitized error so user sees it inline (no internal details)
            yield "\n[Error: LLM request failed. Check your connection and try again.]"
