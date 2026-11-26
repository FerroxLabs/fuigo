import { AcpConnection, Transport } from './connection';

export const CLIENT_ID = 'fuigo-code-extension';

export function initializeParams(version: string) {
  return {
    protocolVersion: 1,
    clientInfo: { name: CLIENT_ID, title: 'Fuigo for VS Code', version },
    clientCapabilities: {
      fs: { readTextFile: true, writeTextFile: true },
      terminal: false,
      _meta: { 'fuigo/hunkTracker': { mode: 'agent_only' }, 'fuigo/mcp/sdk': true },
    },
    // The agent reads clientIdentifier only from the top-level initialize _meta (acp_agent.rs:270-283).
    _meta: { clientIdentifier: CLIENT_ID, 'fuigo/permissionPrompts': true, 'fuigo/mcp/sdk': true },
  };
}

export interface Mode {
  id: string;
  name: string;
  description?: string;
}

export interface SessionInfo {
  sessionId: string;
  modes: Mode[];
  currentModeId: string | undefined;
  /** True when this session was resumed with session/load (its history was replayed as session/update). */
  resumed?: boolean;
}

/** Where the last session id is kept between agent restarts and window reloads (workspaceState in the extension). */
export interface SessionStore {
  get(): string | undefined;
  set(id: string | undefined): void;
}

/** Owns the agent process lifecycle and the current session. vscode-free, so it unit-tests over a fake transport. */
export class AgentController {
  private starting: Promise<SessionInfo> | undefined;
  private canLoad = false;
  private loadingId: string | undefined;
  info: SessionInfo | undefined;
  /** Called right before session/load replays history, so a view can clear what it already shows. */
  onWillLoad: (() => void) | undefined;

  constructor(
    readonly conn: AcpConnection,
    private connect: () => Promise<Transport>,
    private cwd: () => string,
    private version: string,
    /** Client-served MCP servers for session/new _meta (L3's IDE_MCP_SERVERS, coord-notes/1048-vscode-contract.md). */
    private mcpServers: { name: string; serverId: string }[] = [],
    private store?: SessionStore,
  ) {
    conn.onClose(() => {
      this.starting = undefined;
      this.info = undefined;
    });
    conn.onSessionUpdate((sid, u) => {
      if (this.info && sid === this.info.sessionId && u?.sessionUpdate === 'current_mode_update') this.info.currentModeId = u.currentModeId;
    });
  }

  /** Start the agent (if needed) and open a session. Concurrent callers share one start. `fresh` skips resuming. */
  ensureSession(fresh = false): Promise<SessionInfo> {
    if (this.info) return Promise.resolve(this.info);
    this.starting ??= this.start(fresh).catch((e) => {
      this.starting = undefined;
      throw e;
    });
    return this.starting;
  }

  private async start(fresh: boolean): Promise<SessionInfo> {
    if (!this.conn.running) {
      this.conn.attach(await this.connect());
      const init: any = await this.conn.request('initialize', initializeParams(this.version));
      this.canLoad = init?.agentCapabilities?.loadSession === true;
    }
    const last = this.store?.get();
    if (last && this.canLoad && !fresh) {
      try {
        return await this.loadSession(last);
      } catch {
        // The session is gone (deleted, other cwd, older agent): start a fresh one instead.
      }
    }
    return this.openNew();
  }

  /** True for updates of the current session, including the history replayed while session/load runs. */
  isCurrent(sessionId: string) {
    return sessionId === (this.info?.sessionId ?? this.loadingId);
  }

  private sessionParams() {
    const meta: Record<string, unknown> = {};
    if (this.mcpServers.length && this.conn.hasHandler('fuigo/mcp/sdk_call')) meta['fuigo/mcp/servers'] = this.mcpServers;
    return { cwd: this.cwd(), mcpServers: [], _meta: meta };
  }

  private adopt(sessionId: string, r: any, resumed: boolean): SessionInfo {
    this.conn.setSessionId(sessionId);
    this.info = { sessionId, modes: r?.modes?.availableModes ?? [], currentModeId: r?.modes?.currentModeId, resumed };
    this.store?.set(sessionId);
    this.starting = undefined;
    return this.info;
  }

  private async loadSession(sessionId: string): Promise<SessionInfo> {
    this.loadingId = sessionId;
    this.conn.setSessionId(sessionId); // client handlers (fs, permissions) see the session during the replay
    try {
      this.onWillLoad?.();
      const r = await this.conn.request('session/load', { sessionId, ...this.sessionParams() });
      return this.adopt(sessionId, r, true);
    } catch (e) {
      this.conn.setSessionId(undefined);
      throw e;
    } finally {
      this.loadingId = undefined;
    }
  }

  /**
   * A new, empty session. Before the first session exists this must not resume the stored one (the user asked for New),
   * and a start already resuming is followed by session/new. A running turn of the old session is cancelled.
   */
  async newSession(): Promise<SessionInfo> {
    if (!this.info) {
      const s = await this.ensureSession(true);
      if (!s.resumed) return s;
    }
    this.cancel();
    return this.openNew();
  }

  private async openNew(): Promise<SessionInfo> {
    const r: any = await this.conn.request('session/new', this.sessionParams());
    return this.adopt(r.sessionId, r, false);
  }

  async prompt(blocks: unknown[]): Promise<{ stopReason: string }> {
    const s = await this.ensureSession();
    return this.conn.request('session/prompt', { sessionId: s.sessionId, prompt: blocks });
  }

  cancel() {
    if (this.info) this.conn.notify('session/cancel', { sessionId: this.info.sessionId });
  }

  async setMode(modeId: string) {
    const s = await this.ensureSession();
    await this.conn.request('session/set_mode', { sessionId: s.sessionId, modeId });
    s.currentModeId = modeId;
  }

  stop() {
    this.conn.detach();
  }
}
