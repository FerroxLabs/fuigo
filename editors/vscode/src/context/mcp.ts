import { randomBytes } from 'node:crypto';
import type { VsLike } from './types';
import { TOOLS } from './tools';

/**
 * The MCP server name is the model-facing tool namespace (`<name>__<tool>`), and it is the only server identity a
 * permission request carries. Any configured MCP server (user config, a project .mcp.json) may also be called `ide`, and
 * Fuigo routes by name, so a fixed name would let such a server inherit our prompt-free auto-allow. A per-activation
 * random suffix binds the auto-allow to the server this extension registered.
 */
export const IDE_SERVER_NAME = `ide-${randomBytes(4).toString('hex')}`;
export const IDE_SERVER_ID = 'srv_ide';
/** The exact qualified names of our tools, the only ones PermissionUI answers without a prompt. */
export const IDE_TOOL_NAMES: readonly string[] = TOOLS.map((t) => `${IDE_SERVER_NAME}__${t.name}`);
const FALLBACK_PROTOCOL = '2026-07-28'; // what the agent sent in the L0 transcript; we echo the client's own

const ok = (id: unknown, result: unknown) => ({ jsonrpc: '2.0', id, result });
const err = (id: unknown, code: number, message: string) => ({ jsonrpc: '2.0', id, error: { code, message } });

/** Answer one MCP JSON-RPC message. Returns the response envelope, or `{}` for a notification. */
export function handleMcpMessage(vs: VsLike, msg: any): unknown {
  if (!msg || typeof msg !== 'object' || typeof msg.method !== 'string') return err(msg?.id ?? null, -32600, 'invalid request');
  const { id, method, params } = msg;
  if (id === undefined) return {}; // notifications/initialized etc.
  switch (method) {
    case 'initialize':
      return ok(id, {
        protocolVersion: typeof params?.protocolVersion === 'string' ? params.protocolVersion : FALLBACK_PROTOCOL,
        capabilities: { tools: {} },
        serverInfo: { name: 'fuigo-vscode-ide', version: '0.0.1' },
      });
    case 'ping':
      return ok(id, {});
    case 'tools/list':
      return ok(id, { tools: TOOLS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema, annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } })) });
    case 'tools/call': {
      const tool = TOOLS.find((t) => t.name === params?.name);
      if (!tool) return err(id, -32602, `unknown tool ${String(params?.name)}`);
      try {
        return ok(id, { content: [{ type: 'text', text: JSON.stringify(tool.run(vs, params?.arguments ?? {})) }] });
      } catch (e) {
        return ok(id, { isError: true, content: [{ type: 'text', text: e instanceof Error ? e.message : String(e) }] });
      }
    }
    default:
      return err(id, -32601, `no ${method}`);
  }
}

/** Handler for the agent's reverse `fuigo/mcp/sdk_call` request: `{serverId, message}` -> the MCP response envelope. */
export function sdkCallHandler(vs: VsLike) {
  return async (params: any): Promise<unknown> => {
    if (params?.serverId !== IDE_SERVER_ID) throw new Error(`unknown serverId ${String(params?.serverId)}`);
    return handleMcpMessage(vs, params.message);
  };
}
