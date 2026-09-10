//! Actual ACP → discovery → next-request schema activation, with fake inference.
#[allow(dead_code)]
mod acp_harness;
use acp_harness::{AutoApproveClient, RPC_TIMEOUT, connect_client, new_session, prompt_turn, run_agent_test, spawn_agent_local_with_config};
use agent_client_protocol::{self as acp, Agent as _};
use fuigo_test_support::{ScriptedResponse, SseEvent};
use serde_json::{Value,json};

fn reply_tool(name: &str, args: Value) -> ScriptedResponse {
    reply_tools(vec![(name, args)])
}

fn reply_tools(calls: Vec<(&str, Value)>) -> ScriptedResponse {
    let calls: Vec<_> = calls.into_iter().enumerate().map(|(index, (name, args))| json!({
        "index":index,"id":format!("discovery-call-{index}"),"type":"function",
        "function":{"name":name,"arguments":args.to_string()}
    })).collect();
    ScriptedResponse::sse(vec![SseEvent::data(json!({
        "id":"native-discovery-fixture", "object":"chat.completion.chunk", "created":0, "model":"test-model",
        "choices":[{"index":0,"delta":{"role":"assistant","tool_calls":calls},"finish_reason":"tool_calls"}]
    }).to_string()),SseEvent::data("[DONE]")])
}

#[test]
fn native_discovery_activates_next_request_and_rejects_undiscovered_actions() {
    unsafe {std::env::set_var("FUIGO_TOOL_PRESENTATION","adaptive");}
    run_agent_test(|cwd,mock| async move {
        mock.set_models(vec![fuigo_test_support::MockModelEntry::new("test-model"),fuigo_test_support::MockModelEntry::new("test-model-alternate")]);
        std::fs::write(cwd.join("AGENTS.md"),"Retain NATIVE_DISCOVERY_POLICY_719.\n").unwrap();
        let mut config=fuigo_shell::agent::config::Config::default();
        config.session.title_policy=Some(fuigo_shell::agent::config::TitlePolicy::Local);
        let (conn,_)=connect_client(AutoApproveClient,"native-discovery-test",spawn_agent_local_with_config(config)).await;
        let session=new_session(&conn,&cwd).await;
        mock.enqueue_response("/v1/chat/completions",reply_tool("search_tool",json!({"query":"image_gen","scope":"native"})));
        prompt_turn(&conn,&session,"Discover the image tool, but do not execute it; then finish.").await;
        let requests:Vec<Value>=mock.requests().iter().filter(|r|r.path=="/v1/chat/completions")
            .filter_map(|r|r.body.as_ref().and_then(|b|serde_json::from_str(&b.to_string()).ok())).collect();
        let has=|v:&Value,name:&str|v["tools"].as_array().is_some_and(|tools|tools.iter().any(|t|t["function"]["name"]==name));
        assert!(requests.len()>=2,"discovery must yield a new model request");
        assert!(!has(&requests[0],"image_gen"));
        assert!(has(&requests[1],"image_gen"));
        for request in &requests[..2] {
            assert!(has(request,"read_file") && has(request,"use_tool") && has(request,"search_tool"));
            assert!(request["messages"].to_string().contains("NATIVE_DISCOVERY_POLICY_719"));
        }
        let hostile=new_session(&conn,&cwd).await;
        mock.enqueue_response("/v1/chat/completions",reply_tool("image_gen",json!({"prompt":"must never execute"})));
        let result=tokio::time::timeout(RPC_TIMEOUT,conn.prompt(acp::PromptRequest::new(hostile,
            vec![acp::ContentBlock::Text(acp::TextContent::new("Do not run image generation."))]))).await.unwrap();
        assert!(result.unwrap_err().to_string().contains("not advertised"),"undiscovered action was not rejected before dispatch");
        let same_batch=new_session(&conn,&cwd).await;
        mock.enqueue_response("/v1/chat/completions",reply_tools(vec![
            ("search_tool",json!({"query":"image_gen","scope":"native"})),
            ("image_gen",json!({"prompt":"must never execute in discovery response"})),
        ]));
        let result=tokio::time::timeout(RPC_TIMEOUT,conn.prompt(acp::PromptRequest::new(same_batch,
            vec![acp::ContentBlock::Text(acp::TextContent::new("Discover only; do not generate an image."))]))).await.unwrap();
        assert!(result.unwrap_err().to_string().contains("not advertised"),"same-response discovery must not authorize a hidden action");
        // A fresh agent must rebuild presentation from durable hints, not the
        // old actor's mutable snapshot or conversation-tool output.
        drop(conn);
        let mut config=fuigo_shell::agent::config::Config::default();
        config.session.title_policy=Some(fuigo_shell::agent::config::TitlePolicy::Local);
        let (resumed,_)=connect_client(AutoApproveClient,"native-discovery-resume",spawn_agent_local_with_config(config)).await;
        tokio::time::timeout(RPC_TIMEOUT,resumed.load_session(acp::LoadSessionRequest::new(session.clone(),cwd.clone())))
            .await.unwrap().expect("fresh agent must load saved session");
        let before=mock.requests().len();
        prompt_turn(&resumed,&session,"Finish without executing any tools.").await;
        let requests=mock.requests();
        let next:Value=requests[before..].iter().find(|r|r.path=="/v1/chat/completions")
            .and_then(|r|r.body.as_ref()).map(|body|serde_json::from_str(&body.to_string()).unwrap()).unwrap();
        assert!(has(&next,"image_gen"),"fresh agent lost the discovered schema hint");
        assert!(next["messages"].to_string().contains("NATIVE_DISCOVERY_POLICY_719"),"reload lost canonical instructions");
        for round in 0..2 {
            prompt_turn(&resumed,&session,&format!("Continuity fixture round {round}: {}", "completed observation; ".repeat(600))).await;
            acp_harness::ext_method(&resumed,"fuigo/compact_conversation",json!({
                "session_id":session.to_string(),"user_context":"Preserve the user's instructions; summarize completed observations."
            })).await;
            let before=mock.requests().len();
            // Rediscovery is allowed on a new task, but must preserve eligibility
            // and canonical instructions after each real compaction.
            mock.enqueue_response("/v1/chat/completions",reply_tool("search_tool",json!({"query":"image_gen","scope":"native"})));
            prompt_turn(&resumed,&session,"Discover image_gen without executing it, then finish.").await;
            let captured=mock.requests();
            let bodies:Vec<Value>=captured[before..].iter().filter(|r|r.path=="/v1/chat/completions")
                .filter_map(|r|r.body.as_ref().map(|b|serde_json::from_str(&b.to_string()).unwrap())).collect();
            assert!(bodies.iter().any(|b|has(b,"image_gen")),"compaction {round} lost native reachability");
            assert!(bodies.iter().all(|b|b["messages"].to_string().contains("NATIVE_DISCOVERY_POLICY_719")),"compaction {round} lost canonical instructions");
        }
        tokio::time::timeout(RPC_TIMEOUT,resumed.set_session_model(acp::SetSessionModelRequest::new(
            session.clone(),acp::ModelId::new("test-model-alternate")
        ))).await.unwrap().expect("explicit model switch");
        let before=mock.requests().len();
        mock.enqueue_response("/v1/chat/completions",reply_tool("search_tool",json!({"query":"image_gen","scope":"native"})));
        prompt_turn(&resumed,&session,"Discover image_gen without executing it, then finish.").await;
        let captured=mock.requests();
        let bodies:Vec<Value>=captured[before..].iter().filter(|r|r.path=="/v1/chat/completions")
            .filter_map(|r|r.body.as_ref().map(|b|serde_json::from_str(&b.to_string()).unwrap())).collect();
        assert!(!bodies.is_empty());
        assert!(bodies.iter().all(|b|b["model"]=="test-model-alternate"),"switch did not reach inference requests");
        assert!(bodies.iter().any(|b|has(b,"image_gen")),"switch lost native reachability");
        assert!(bodies.iter().all(|b|b["messages"].to_string().contains("NATIVE_DISCOVERY_POLICY_719")),"switch lost canonical instructions");
        // Reattach to the resident actor: the new host's pinned delivery tools
        // must take effect, not the original actor's startup policy.
        let pinned=new_session(&resumed,&cwd).await;
        tokio::time::timeout(RPC_TIMEOUT,resumed.load_session(acp::LoadSessionRequest::new(pinned.clone(),cwd.clone())
            .meta(json!({"startupHints":{"deliveryTools":["image_gen"],"nonInteractive":true}}).as_object().cloned())))
            .await.unwrap().expect("host attachment policy");
        let before=mock.requests().len();
        prompt_turn(&resumed,&pinned,"Finish without calling tools.").await;
        let captured=mock.requests();
        let first:Value=captured[before..].iter().find(|r|r.path=="/v1/chat/completions")
            .and_then(|r|r.body.as_ref()).map(|b|serde_json::from_str(&b.to_string()).unwrap()).unwrap();
        assert!(has(&first,"image_gen"),"reattached host delivery tool was hidden");
        tokio::time::timeout(RPC_TIMEOUT,resumed.load_session(acp::LoadSessionRequest::new(pinned.clone(),cwd.clone())
            .meta(json!({"startupHints":{"deliveryTools":[],"nonInteractive":true}}).as_object().cloned())))
            .await.unwrap().expect("host pin removal");
        let before=mock.requests().len();
        prompt_turn(&resumed,&pinned,"Finish without calling tools.").await;
        let captured=mock.requests();
        let first:Value=captured[before..].iter().find(|r|r.path=="/v1/chat/completions")
            .and_then(|r|r.body.as_ref()).map(|b|serde_json::from_str(&b.to_string()).unwrap()).unwrap();
        assert!(!has(&first,"image_gen"),"removed host pin remained advertised");
    });
}
