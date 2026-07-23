import unittest
from unittest.mock import MagicMock, patch

import llm


class CallModelMaxTokensTests(unittest.TestCase):
    def test_openai_compatible_uses_configured_max_tokens(self):
        fake_response = MagicMock()
        fake_response.choices = [MagicMock(message=MagicMock(content="ok"))]
        fake_client = MagicMock()
        fake_client.chat.completions.create.return_value = fake_response
        with patch("openai.OpenAI", return_value=fake_client), \
             patch("httpx.Client"):
            result = llm.call_model("prompt", {
                "provider": "openai-compatible", "id": "my-model",
                "url": "http://localhost:8000/v1", "max_tokens": 8192,
            })
        self.assertEqual(result, "ok")
        _, kwargs = fake_client.chat.completions.create.call_args
        self.assertEqual(kwargs["max_tokens"], 8192)

    def test_openai_compatible_defaults_max_tokens_to_2048(self):
        fake_response = MagicMock()
        fake_response.choices = [MagicMock(message=MagicMock(content="ok"))]
        fake_client = MagicMock()
        fake_client.chat.completions.create.return_value = fake_response
        with patch("openai.OpenAI", return_value=fake_client), \
             patch("httpx.Client"):
            llm.call_model("prompt", {
                "provider": "openai-compatible", "id": "my-model",
                "url": "http://localhost:8000/v1",
            })
        _, kwargs = fake_client.chat.completions.create.call_args
        self.assertEqual(kwargs["max_tokens"], 2048)

    def test_anthropic_uses_configured_max_tokens(self):
        fake_response = MagicMock()
        fake_response.content = [MagicMock(text="ok")]
        fake_client = MagicMock()
        fake_client.messages.create.return_value = fake_response
        with patch("anthropic.Anthropic", return_value=fake_client):
            result = llm.call_model("prompt", {
                "provider": "anthropic", "id": "claude-x", "api_key": "sk-ant", "max_tokens": 4096,
            })
        self.assertEqual(result, "ok")
        _, kwargs = fake_client.messages.create.call_args
        self.assertEqual(kwargs["max_tokens"], 4096)

    def test_vllm_uses_configured_max_tokens(self):
        fake_response = MagicMock()
        fake_response.choices = [MagicMock(message=MagicMock(content="ok"))]
        fake_client = MagicMock()
        fake_client.chat.completions.create.return_value = fake_response
        with patch("openai.OpenAI", return_value=fake_client):
            llm.call_model("prompt", {"provider": "vllm", "id": "my-model", "max_tokens": 16384})
        _, kwargs = fake_client.chat.completions.create.call_args
        self.assertEqual(kwargs["max_tokens"], 16384)


class CallModelTimeoutTests(unittest.TestCase):
    """Without an explicit timeout, a stalled/unresponsive endpoint can block
    a solve loop for a very long time (up to ~600s on the OpenAI SDK's own
    default) before erroring — long enough to look like the whole run froze.
    Every provider client must be constructed with an explicit, bounded
    timeout instead of inheriting the SDK's own default."""

    def _fake_openai_response(self):
        fake_response = MagicMock()
        fake_response.choices = [MagicMock(message=MagicMock(content="ok"))]
        return fake_response

    def test_openai_client_gets_explicit_timeout(self):
        fake_client = MagicMock()
        fake_client.chat.completions.create.return_value = self._fake_openai_response()
        with patch("openai.OpenAI", return_value=fake_client) as openai_cls:
            llm.call_model("prompt", {"provider": "openai", "id": "gpt-x", "api_key": "sk-x"})
        _, kwargs = openai_cls.call_args
        self.assertEqual(kwargs["timeout"], llm.LLM_REQUEST_TIMEOUT_S)

    def test_vllm_client_gets_explicit_timeout(self):
        fake_client = MagicMock()
        fake_client.chat.completions.create.return_value = self._fake_openai_response()
        with patch("openai.OpenAI", return_value=fake_client) as openai_cls:
            llm.call_model("prompt", {"provider": "vllm", "id": "my-model"})
        _, kwargs = openai_cls.call_args
        self.assertEqual(kwargs["timeout"], llm.LLM_REQUEST_TIMEOUT_S)

    def test_huggingface_client_gets_explicit_timeout(self):
        fake_client = MagicMock()
        fake_client.chat.completions.create.return_value = self._fake_openai_response()
        with patch.object(llm.config, "HF_ENDPOINTS", {"my-model": "https://hf.example"}), \
             patch("openai.OpenAI", return_value=fake_client) as openai_cls:
            llm.call_model("prompt", {"provider": "huggingface", "id": "my-model"})
        _, kwargs = openai_cls.call_args
        self.assertEqual(kwargs["timeout"], llm.LLM_REQUEST_TIMEOUT_S)

    def test_openai_compatible_http_client_gets_explicit_timeout(self):
        fake_client = MagicMock()
        fake_client.chat.completions.create.return_value = self._fake_openai_response()
        with patch("openai.OpenAI", return_value=fake_client), \
             patch("httpx.Client") as httpx_client_cls:
            llm.call_model("prompt", {
                "provider": "openai-compatible", "id": "my-model", "url": "http://localhost:8000/v1",
            })
        _, kwargs = httpx_client_cls.call_args
        self.assertEqual(kwargs["timeout"], llm.LLM_REQUEST_TIMEOUT_S)

    def test_anthropic_client_gets_explicit_timeout(self):
        fake_response = MagicMock()
        fake_response.content = [MagicMock(text="ok")]
        fake_client = MagicMock()
        fake_client.messages.create.return_value = fake_response
        with patch("anthropic.Anthropic", return_value=fake_client) as anthropic_cls:
            llm.call_model("prompt", {"provider": "anthropic", "id": "claude-x", "api_key": "sk-ant"})
        _, kwargs = anthropic_cls.call_args
        self.assertEqual(kwargs["timeout"], llm.LLM_REQUEST_TIMEOUT_S)


if __name__ == "__main__":
    unittest.main()
