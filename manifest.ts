import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getPluginBooleanConfig, loadPluginEnv } from '@jshookmcp/extension-sdk/plugin';
import type {
  DomainManifest,
  PluginContract,
  PluginLifecycleContext,
  ToolArgs,
  ToolHandlerDeps,
} from '@jshookmcp/extension-sdk/plugin';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

loadPluginEnv(import.meta.url);

type JsonObject = Record<string, unknown>;
type TextToolResponse = { content: Array<{ type: 'text'; text: string }> };
type RemoteToolDef = { name: string; description?: string; inputSchema?: unknown };
type RemoteListToolsResult = { tools?: RemoteToolDef[]; nextCursor?: string };
type RemoteCallResult = { content?: Array<{ type?: string; text?: string }> };

function toText(payload: unknown): TextToolResponse {
  return { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }] };
}

function toErr(tool: string, error: unknown, extra: JsonObject = {}): TextToolResponse {
  return toText({ success: false, tool, error: error instanceof Error ? error.message : String(error), ...extra });
}

function assertLoopbackUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`Invalid BURP_MCP_SSE_URL: ${value}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`Only http/https are allowed, got ${url.protocol}`);
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const loopback = host === '127.0.0.1' || host === 'localhost' || host === '::1';
  if (!loopback) throw new Error(`Only loopback hosts are allowed (127.0.0.1/localhost/::1), got ${host}`);
  return url.toString();
}

function safeParseToolContent(result: unknown): unknown {
  const maybe = result as RemoteCallResult;
  if (!maybe || !Array.isArray(maybe.content) || maybe.content.length === 0) return result;
  const first = maybe.content[0];
  if (!first || typeof first !== 'object' || typeof first.text !== 'string') return result;
  try {
    return JSON.parse(first.text);
  } catch {
    return first.text;
  }
}

class BurpMcpSseHandlers {
  private activeUrl: string;
  private readonly authToken?: string;

  constructor(private readonly sseUrl: string, authToken?: string) {
    this.sseUrl = assertLoopbackUrl(sseUrl);
    this.activeUrl = this.sseUrl;
    this.authToken = authToken?.trim() || undefined;
  }

  private async withTimeout<T>(promise: Promise<T>, ms: number, msg: string): Promise<T> {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => setTimeout(() => reject(new Error(msg)), ms)),
    ]);
  }

  private candidateUrls(): string[] {
    const primary = new URL(this.activeUrl || this.sseUrl);
    const urls = [primary.toString()];
    if (primary.pathname.endsWith('/sse')) {
      const fallback = new URL(primary.toString());
      fallback.pathname = fallback.pathname.replace(/\/sse$/, '') || '/';
      urls.push(fallback.toString());
    } else {
      const fallback = new URL(primary.toString());
      fallback.pathname = `${fallback.pathname.replace(/\/$/, '')}/sse`;
      urls.push(fallback.toString());
    }
    return [...new Set(urls)];
  }

  private async connectClient(): Promise<{ client: Client; transport: SSEClientTransport; activeUrl: string }> {
    const requestInit = this.authToken
      ? { headers: { Authorization: `Bearer ${this.authToken}` } }
      : undefined;

    let lastError: unknown = null;
    for (const candidateUrl of this.candidateUrls()) {
      const client = new Client(
        { name: 'jshook-burp-mcp-sse', version: '0.1.0' },
        { capabilities: {} },
      );
      const transport = new SSEClientTransport(new URL(candidateUrl), { requestInit });
      try {
        await this.withTimeout(client.connect(transport), 5000, `connect timeout for ${candidateUrl}`);
        return { client, transport, activeUrl: candidateUrl };
      } catch (error) {
        lastError = error;
        try {
          await transport.close();
        } catch {
          // best effort
        }
      }
    }

    if (lastError instanceof Error) throw lastError;
    throw new Error(lastError ? String(lastError) : 'Unable to establish SSE connection');
  }

  async handleStatus(_args: ToolArgs = {}): Promise<TextToolResponse> {
    let transport: SSEClientTransport | null = null;
    try {
      const connected = await this.connectClient();
      transport = connected.transport;
      this.activeUrl = connected.activeUrl;
      const listed = (await this.withTimeout(
        connected.client.listTools(),
        8000,
        'tools/list timeout from remote Burp MCP server',
      )) as RemoteListToolsResult;
      const tools = Array.isArray(listed?.tools) ? listed.tools : [];

      return toText({
        success: true,
        endpoint: this.activeUrl,
        transport: 'sse',
        toolCount: tools.length,
        toolNames: tools.map((tool) => tool.name),
        serverVersion: connected.client.getServerVersion(),
        serverCapabilities: connected.client.getServerCapabilities(),
      });
    } catch (error) {
      return toErr('burp_mcp_sse_status', error, {
        endpoint: this.sseUrl,
        hint: 'Ensure Burp official MCP server is running on loopback and BURP_MCP_SSE_URL is correct',
      });
    } finally {
      try {
        await transport?.close();
      } catch {
        // best effort
      }
    }
  }

  async handleListTools(args: ToolArgs = {}): Promise<TextToolResponse> {
    let transport: SSEClientTransport | null = null;
    try {
      const cursor = typeof args.cursor === 'string' ? args.cursor : undefined;
      const connected = await this.connectClient();
      transport = connected.transport;
      this.activeUrl = connected.activeUrl;

      const listed = (await this.withTimeout(
        connected.client.listTools({ cursor }),
        8000,
        'tools/list timeout from remote Burp MCP server',
      )) as RemoteListToolsResult;

      const tools = Array.isArray(listed?.tools) ? listed.tools : [];
      return toText({
        success: true,
        endpoint: this.activeUrl,
        count: tools.length,
        nextCursor: listed?.nextCursor,
        tools: tools.map((tool) => ({
          name: tool.name,
          description: tool.description ?? '',
          inputSchema: tool.inputSchema ?? null,
        })),
      });
    } catch (error) {
      return toErr('burp_mcp_sse_list_tools', error, { endpoint: this.sseUrl });
    } finally {
      try {
        await transport?.close();
      } catch {
        // best effort
      }
    }
  }

  async handleCallTool(args: ToolArgs = {}): Promise<TextToolResponse> {
    let transport: SSEClientTransport | null = null;
    const name = typeof args.name === 'string' ? args.name : '';
    if (!name) {
      return toErr('burp_mcp_sse_call_tool', new Error('name is required'));
    }

    const rawArguments = args.arguments;
    const toolArgs =
      rawArguments && typeof rawArguments === 'object' && !Array.isArray(rawArguments)
        ? (rawArguments as Record<string, unknown>)
        : {};

    try {
      const connected = await this.connectClient();
      transport = connected.transport;
      this.activeUrl = connected.activeUrl;
      const result = await this.withTimeout(
        connected.client.callTool({ name, arguments: toolArgs }),
        12000,
        `tools/call timeout for remote tool ${name}`,
      );

      return toText({
        success: true,
        endpoint: this.activeUrl,
        forwardedTool: name,
        result: safeParseToolContent(result),
      });
    } catch (error) {
      return toErr('burp_mcp_sse_call_tool', error, { endpoint: this.sseUrl, forwardedTool: name });
    } finally {
      try {
        await transport?.close();
      } catch {
        // best effort
      }
    }
  }
}

const tools: Tool[] = [
  {
    name: 'burp_mcp_sse_status',
    description: 'Check connectivity to Burp official MCP server over SSE and return tool catalog summary.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'burp_mcp_sse_list_tools',
    description: 'List tools exposed by remote Burp MCP server over SSE.',
    inputSchema: {
      type: 'object',
      properties: {
        cursor: { type: 'string', description: 'Optional pagination cursor' },
      },
    },
  },
  {
    name: 'burp_mcp_sse_call_tool',
    description: 'Call any remote tool exposed by Burp MCP server over SSE.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Remote tool name' },
        arguments: {
          type: 'object',
          additionalProperties: true,
          description: 'Arguments object forwarded to remote tool',
        },
      },
      required: ['name'],
    },
  },
];

const DEP_KEY = 'burpMcpSseHandlers';
const DOMAIN = 'burp-mcp-sse-call-tool';

function bind(methodName: string) {
  return (deps: ToolHandlerDeps) => async (args: ToolArgs) => {
    const handlers = deps[DEP_KEY] as Record<string, unknown>;
    const method = handlers[methodName];
    if (typeof method !== 'function') {
      throw new Error(`Missing Burp SSE handler: ${methodName}`);
    }
    return method.call(handlers, args ?? {});
  };
}

const domainManifest: DomainManifest = {
  kind: 'domain-manifest',
  version: 1,
  domain: DOMAIN,
  depKey: DEP_KEY,
  profiles: ['workflow', 'full', 'reverse'],
  ensure() {
    const sseUrl = process.env.BURP_MCP_SSE_URL ?? 'http://127.0.0.1:9876';
    const authToken = process.env.BURP_MCP_AUTH_TOKEN;
    return new BurpMcpSseHandlers(sseUrl, authToken);
  },
  registrations: [
    { tool: tools[0]!, domain: DOMAIN, bind: bind('handleStatus') },
    { tool: tools[1]!, domain: DOMAIN, bind: bind('handleListTools') },
    { tool: tools[2]!, domain: DOMAIN, bind: bind('handleCallTool') },
  ],
};

const plugin: PluginContract = {
  manifest: {
    kind: 'plugin-manifest',
    version: 1,
    id: 'io.github.vmoranv.burp-mcp-sse-call-tool',
    name: 'Burp MCP SSE',
    pluginVersion: '0.1.0',
    entry: 'manifest.js',
    description: 'Plugin exposing burp_mcp_sse_status, burp_mcp_sse_list_tools, and burp_mcp_sse_call_tool.',
    compatibleCore: '>=0.1.0',
    permissions: {
      network: { allowHosts: ['127.0.0.1', 'localhost', '::1'] },
      process: { allowCommands: [] },
      filesystem: { readRoots: [], writeRoots: [] },
      toolExecution: {
        allowTools: ['burp_mcp_sse_status', 'burp_mcp_sse_list_tools', 'burp_mcp_sse_call_tool'],
      },
    },
    activation: { onStartup: false, profiles: ['workflow', 'full', 'reverse'] },
    contributes: {
      domains: [domainManifest],
      workflows: [],
      configDefaults: { 'plugins.burp-mcp-sse-call-tool.enabled': true },
      metrics: [
        'burp_mcp_sse_status_calls_total',
        'burp_mcp_sse_list_tools_calls_total',
        'burp_mcp_sse_call_tool_calls_total',
      ],
    },
  },
  onLoad(ctx: PluginLifecycleContext): void {
    ctx.setRuntimeData('loadedAt', new Date().toISOString());
  },
  onValidate(ctx: PluginLifecycleContext) {
    const enabled = getPluginBooleanConfig(ctx, 'burp-mcp-sse-call-tool', 'enabled', true);
    if (!enabled) return { valid: false, errors: ['Plugin disabled by config'] };
    return { valid: true, errors: [] };
  },
};

export default plugin;
