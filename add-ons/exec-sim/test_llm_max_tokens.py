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


if __name__ == "__main__":
    unittest.main()
