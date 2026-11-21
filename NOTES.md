# TC notes
- fuigo-sampler/src/client.rs: FuigoRequestHeaders::apply now also sends x-grok-conv-id and x-session-id (both = session id, ungated, all destinations); consts H_GROK_CONV_ID, H_OPENROUTER_SESSION_ID, PROVIDER_CACHE_HEADERS (kept out of the x-fuigo-* arrays, whose test asserts that prefix). Test provider_cache_headers_carry_the_session_id_everywhere.
- fuigo-sampling-types responses_tests.rs: pinning tests main_turn_and_side_call_share_one_prompt_cache_key (T2), system_prompt_is_an_input_item_not_instructions (T3). No code change for either.
- Docs: xAI https://docs.x.ai/developers/advanced-api-usage/prompt-caching names x-grok-conv-id. OpenRouter https://openrouter.ai/docs/guides/best-practices/prompt-caching.md documents session_id body field or x-session-id header (falls back to prompt_cache_key).
- Release note: xAI and OpenRouter prompt-cache routing headers restored/added (x-grok-conv-id, x-session-id).
