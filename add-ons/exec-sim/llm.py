import config

# Every provider client below gets this as its request timeout. Without an
# explicit value, the openai-compatible/ollama path (its own httpx.Client)
# defaults to httpx's 5s timeout — too short for real generation with a
# large max_tokens — while every other path inherits the OpenAI/Anthropic
# SDK's own default (~600s for OpenAI), which lets a stalled/unresponsive
# endpoint block a solve loop for up to 10 minutes per turn before it's
# visibly an error. A single bounded value here means a hung endpoint fails
# fast and loud instead of silently freezing the whole run.
LLM_REQUEST_TIMEOUT_S = 120.0


def call_model(prompt: str, model_cfg: dict, system_prompt: str = "",
               messages: list = None) -> str:
    """
    Call any supported model with a single user prompt or a full message list.
    If `messages` is given it is used directly (multi-turn); otherwise a
    single user turn is built from `prompt`.
    """
    provider = model_cfg["provider"]
    model_id = model_cfg["id"]
    max_tokens = int(model_cfg.get("max_tokens") or 2048)

    if messages is None:
        messages = [{"role": "user", "content": prompt}]

    if provider == "anthropic":
        import anthropic as _ant
        _client = _ant.Anthropic(
            api_key=model_cfg.get("api_key") or config.ANTHROPIC_API_KEY,
            timeout=LLM_REQUEST_TIMEOUT_S,
        )
        kwargs = dict(model=model_id, max_tokens=max_tokens, messages=messages)
        if system_prompt:
            kwargs["system"] = system_prompt
        resp = _client.messages.create(**kwargs)
        return resp.content[0].text

    elif provider in ("openai", "openrouter"):
        import openai
        api_key  = model_cfg.get("api_key") or (
            config.OPENROUTER_API_KEY if provider == "openrouter" else config.OPENAI_API_KEY)
        base_url = "https://openrouter.ai/api/v1" if provider == "openrouter" else None
        kw = {"api_key": api_key, "timeout": LLM_REQUEST_TIMEOUT_S}
        if base_url:
            kw["base_url"] = base_url
        _client = openai.OpenAI(**kw)
        oai_msgs = []
        if system_prompt:
            oai_msgs.append({"role": "system", "content": system_prompt})
        oai_msgs.extend(messages)
        _reasoning_models = {"o1", "o1-mini", "o1-preview", "o3", "o3-mini"}
        token_param = "max_completion_tokens" if model_id in _reasoning_models else "max_tokens"
        resp = _client.chat.completions.create(
            model=model_id, messages=oai_msgs, **{token_param: max_tokens})
        return resp.choices[0].message.content or ""

    elif provider == "vllm":
        import openai
        _client = openai.OpenAI(api_key="EMPTY", base_url=config.VLLM_BASE_URL, timeout=LLM_REQUEST_TIMEOUT_S)
        oai_msgs = []
        if system_prompt:
            oai_msgs.append({"role": "system", "content": system_prompt})
        oai_msgs.extend(messages)
        resp = _client.chat.completions.create(
            model=model_id, messages=oai_msgs, max_tokens=max_tokens)
        return (resp.choices[0].message.content or "") if resp.choices else ""

    elif provider in ("openai-compatible", "ollama"):
        import openai
        import httpx

        url = model_cfg.get("url")
        api_key = model_cfg.get("api_key") or "EMPTY"
        enforce_ssl = model_cfg.get("enforce_ssl", True)

        http_client = httpx.Client(verify=enforce_ssl, timeout=LLM_REQUEST_TIMEOUT_S)
        _client = openai.OpenAI(api_key=api_key, base_url=url, http_client=http_client)

        oai_msgs = []
        if system_prompt:
            oai_msgs.append({"role": "system", "content": system_prompt})
        oai_msgs.extend(messages)

        resp = _client.chat.completions.create(
            model=model_id, messages=oai_msgs, max_tokens=max_tokens)
        return (resp.choices[0].message.content or "") if resp.choices else ""

    elif provider == "huggingface":
        import openai
        endpoint_url = config.HF_ENDPOINTS.get(model_id)
        if not endpoint_url:
            raise ValueError(f"No HF endpoint URL for {model_id!r}. Add it to HF_ENDPOINTS.")
        _client = openai.OpenAI(api_key=config.HF_API_KEY, base_url=endpoint_url + "/v1", timeout=LLM_REQUEST_TIMEOUT_S)
        oai_msgs = []
        if system_prompt:
            oai_msgs.append({"role": "system", "content": system_prompt})
        oai_msgs.extend(messages)
        resp = _client.chat.completions.create(model="tgi", messages=oai_msgs, max_tokens=max_tokens)
        return resp.choices[0].message.content or ""

    else:
        raise ValueError(f"Unknown provider: {provider!r}")
