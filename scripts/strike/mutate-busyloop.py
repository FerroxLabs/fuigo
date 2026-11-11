#!/usr/bin/env python3
"""Mutate the production Rust port, run its TSV/trace tests, and restore it.
Run on the host with --runner pointing to the lane's container-only cargo wrapper.
All expected nonzero exits are retained as RED evidence, never hidden by should_panic.
"""
import argparse,subprocess,re,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--runner',required=True);p.add_argument('--evidence',required=True);p.add_argument('--only',default='');a=p.parse_args()
root=Path(__file__).resolve().parents[2];source=root/'crates/codegen/fuigo-sampling-types/src/refusal.rs';original=source.read_text();out=Path(a.evidence);out.mkdir(parents=True,exist_ok=True)
def replace(s,old,new):
 assert old in s,old
 return s.replace(old,new,1)
def swap(s):
 return re.sub(r'else if terminal_text \{\s*Action::Stop\s*\} else if held \{\s*Action::RetryOnce\s*\} else if transient \{\s*Action::Backoff\s*\}', 'else if held { Action::RetryOnce } else if transient { Action::Backoff } else if terminal_text { Action::Stop }',s,count=1)
def drop_d12(s):
 start=s.index('const TEXT_RULES:');end=s.index('const RATE_TEXT:',start);part=s[start:end]
 pat=r'\s*\(&\["monthly budget"\], "keyBudget"\),'
 m=re.search(pat,part);assert m;part=part[:m.start()]+part[m.end():]
 i=part.index('    (&["bot has reached its"],');part=part[:i]+m[0]+'\n'+part[i:];return s[:start]+part+s[end:]
def override(s):
 start=s.index('fn stop_reason');end=s.index('pub fn decide',start);part=s[start:end]
 block=re.search(r'    if let Some\(r\) = first_text\(&s.text, OVERRIDE_TEXT\) \{\s*return r;\s*\}\n',part)[0]
 part=part.replace(block,'');i=part.index('    first_text(&s.text, TEXT_RULES)');part=part[:i]+block+part[i:];return s[:start]+part+s[end:]
def drop_limit(s):
 start=s.index('pub fn fuigo_upstream');end=s.index('#[derive',start);part=s[start:end]
 part,n=re.subn(r'limit: slug\(&e\["limit"\]\)\s*\.or_else\(\|\| slug\(&p\["limit"\]\)\)\s*\.or_else\(\|\| slug\(&pe\["limit"\]\)\),','limit: None,',part,count=1);assert n;return s[:start]+part+s[end:]
mutants={
 'side_call_fatal':lambda s:replace(s, 'if self.role == CallRole::Side {return false;}', 'if false && self.role == CallRole::Side {return false;}'),
 'auth_status_projection':lambda s:replace(s, 'SamplingError::Auth { .. } => (SamplingErrorKind::Auth, None, None, None),', 'SamplingError::Auth { status, .. } => (SamplingErrorKind::Auth, Some(*status), None, None),'),
 'terminal_not_persisted':lambda s:replace(s, 'queue.terminal = true;', 'queue.terminal = false;'),
 'park_compaction':lambda s:replace(s, '&& !turn_parked.is_parked()\n                && !salvage.awaiting_continuation()', '&& !salvage.awaiting_continuation()'),
 'classify_display_string':lambda s:replace(s, 'crate::refusal::extract("resp", status, &headers, &body, chrono::Utc::now())', 'crate::refusal::from_upstream(&self, &user_facing_api_error_message(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR), bytes), chrono::Utc::now())'),
 'child_own_gate':lambda s:replace(s, 'crate::session::quiesce::ancestors_including_self(id)', '[id.to_owned()]'),
 'unknown_values_passthrough':lambda s:re.sub(r'else \{\s*"other"\s*\}', 'else { value }', s, count=1),
 'drop_host_check':lambda s:re.sub(r'host == "fluxrouter.ai"\s*\|\| host.ends_with\(".fluxrouter.ai"\)', 'true', s, count=1),
 'swap_text_transient':swap,
 'drop_401':lambda s:replace(s,'matches!(s.status, 401 | 402 | 403)','matches!(s.status, 402 | 403)'),
 'credit_unresolved_retry':lambda s:replace(replace(s,'    ("credit_unresolved", "unresolved"),\n',''),'const TRANSIENT: &[&str] = &[','const TRANSIENT: &[&str] = &["credit_unresolved",'),
 'drop_d12':drop_d12,
 'ignore_limit':lambda s:replace(s,'match s.limit.as_deref()','match None::<&str>'),
 'drop_known_wait':lambda s:replace(s,'s.status == 429 && s.wait.is_some()','false && s.status == 429 && s.wait.is_some()'),
 'drop_pause':lambda s:replace(s,'else if s.status == 429 {','else if false && s.status == 429 {'),
 'drop_terminal_text':lambda s:replace(s,'else if terminal_text {','else if false && terminal_text {'),
 'drop_mislabel':lambda s:replace(s,'if s.endpoint == "chat"','if false && s.endpoint == "chat"'),
 'mislabel_ignores_header':lambda s:replace(s,'&& !s.hold_header',''),
 'transient_names_stop':lambda s:replace(s,'pub const FINAL_ORDER: &[(&str, &str)] = &[','pub const FINAL_ORDER: &[(&str, &str)] = &[("concurrency","hold"),("batch_concurrency","busy"),'),
 'bool_is_int':lambda s:replace(s,'v.as_u64().filter(|v| *v <= 7200)','v.as_u64().or_else(||v.as_bool().map(u64::from)).filter(|v| *v <= 7200)'),
 'override_after_codes':override,
 'fuigo_drops_limit':drop_limit,
 'no_refresh_exception':lambda s:replace(s,'refreshable\n            && status == 401','false && refreshable\n            && status == 401'),
 'refresh_on_403':lambda s:replace(s,'status == 401','matches!(status,401|403)'),
 'two_refreshes':lambda s:replace(s,'if kind == "refresh_resubmit" {\n            self.state = PromptState::Terminal;', 'if kind == "refresh_resubmit" {\n            self.state = if result.refresh_eligible(status,self.refreshable) {PromptState::AuthRefresh} else {PromptState::Terminal};'),
 'hash_invariant':lambda s:replace(s,'if self.state == PromptState::Terminal {','if self.state == PromptState::Terminal && !["compact","side"].contains(&kind) {'),
 'drop_403':lambda s:replace(s,'matches!(s.status, 401 | 402 | 403)','matches!(s.status, 401 | 402)'),
 'drop_resets_at':lambda s:replace(s,'resets_at: resets\n            .as_str()','resets_at: resets\n            .as_str().filter(|_|false)'),
 'wrong_key_rejected_mark':lambda s:replace(s,'reason == "keyRevoked"','reason == "keyBudget"'),
 'fuigo_first_code_only':lambda s:replace(s,'codes: all_codes,','codes: Vec::new(),'),
 'resubmit_transient_open':lambda s:replace(s,'if kind == "refresh_resubmit" {\n            self.state = PromptState::Terminal;', 'if kind == "refresh_resubmit" {\n            self.state = if matches!(result.action,Action::Backoff|Action::RetryOnce|Action::Pass) {PromptState::Refreshed} else {PromptState::Terminal};'),
 'side_exempt':lambda s:replace(s,'if self.state == PromptState::Terminal {','if self.state == PromptState::Terminal && kind != "side" {'),
}
(out/'refusal.rs.original').write_text(original)
results={}
try:
 for name,mut in mutants.items():
  if a.only and name not in a.only.split(','):continue
  targets = {
   'side_call_fatal': root/'crates/codegen/fuigo-shell/src/session/acp_session_impl/sampler_turn.rs',
   'auth_status_projection': root/'crates/codegen/fuigo-sampler/src/events.rs',
   'terminal_not_persisted': root/'crates/codegen/fuigo-shell/src/session/acp_session_impl/held_wakes.rs',
   'park_compaction': root/'crates/codegen/fuigo-shell/src/session/acp_session_impl/turn.rs',
   'unknown_values_passthrough': root/'crates/codegen/fuigo-sampling-types/src/upstream_vocab.rs',
   'classify_display_string': root/'crates/codegen/fuigo-sampling-types/src/error.rs',
   'child_own_gate': root/'crates/codegen/fuigo-shell/src/session/acp_session_impl/sampler_turn.rs',
  }
  target=targets.get(name,source)
  baseline=target.read_text() if target!=source else original
  changed=mut(baseline);assert changed!=baseline,name;target.write_text(changed)
  with (out/(name+'.log')).open('w') as log:
   command = ['cargo','test','-p','fuigo-sampling-types','--test',
       'upstream_projection' if name=='unknown_values_passthrough' else
       'host_scope' if name=='drop_host_check' else
       'boundary_refusal' if name=='classify_display_string' else 'busyloop_parity',
       '--','--nocapture']
   if name=='child_own_gate': command = ['cargo','test','-p','fuigo-shell','--lib','r4_rebuilt_child_gate_obeys_parent_stop_and_pause','--','--nocapture']
   regression = {
    'side_call_fatal': 'r2_side_refusal_leaves_main_open',
    'auth_status_projection': 'r2_wire_golden_terminal_paths',
    'terminal_not_persisted': 'r2_terminal_without_wakes_survives_reload',
    'park_compaction': 'parked_turn_past_compact_threshold_does_not_auto_compact',
   }.get(name)
   if regression: command = ['cargo','test','-p','fuigo-shell','--lib',regression,'--','--nocapture']
   proc=subprocess.run([a.runner,*command],stdout=log,stderr=subprocess.STDOUT)
  target.write_text(baseline)
  output=(out/(name+'.log')).read_text();killed=proc.returncode!=0 and 'test result: FAILED' in output
  if regression: killed = killed and regression in output
  if name=='classify_display_string': killed = killed and '    h5_raw_provider_message_survives_display_selection' in output
  if name=='child_own_gate': killed = killed and 'r4_rebuilt_child_gate_obeys_parent_stop_and_pause' in output
  if name=='drop_host_check': killed = killed and '    s3a_non_flux_gemini_resource_exhausted_keeps_retry' in output
  results[name]='KILLED' if killed else 'SURVIVED' if proc.returncode==0 else 'BUILD_ERROR'
  print(name,results[name],flush=True)
  if results[name]=='BUILD_ERROR':break
finally:
 source.write_text(original)
 if 'target' in globals():target.write_text(baseline)
(out/'results.json').write_text(json.dumps(results,indent=2)+'\n')
raise SystemExit(any(v!='KILLED' for v in results.values()))
