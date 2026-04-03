import { createExtension, jsonResponse, errorResponse } from '@jshookmcp/extension-sdk/plugin';
import type { PluginLifecycleContext, ToolArgs, ToolResponse } from '@jshookmcp/extension-sdk/plugin';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

const PLUGIN_SLUG = 'burp-mcp-sse-call-tool';

type JsonObject = Record<string, unknown>;
type RemoteToolDef = { name: string; description?: string; inputSchema?: unknown };
type RemoteListToolsResult = { tools?: RemoteToolDef[]; nextCursor?: string };
type RemoteCallResult = { content?: Array<{ type?: string; text?: string }> };

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

function getPluginBooleanConfig(
  ctx: PluginLifecycleContext,
  slug: string,
  key: string,
  fallback: boolean,
): boolean {
  const value = ctx.getConfig(`plugins.${slug}.${key}`, fallback);
  return typeof value === 'boolean' ? value : fallback;
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
      const fallback = new URL(this.activeUrl.toString());
      fallback.pathname = `${fallback.pathname.replace(/\/$/, '')}/sse`;
      urls.push(fallback.toString());
    }
    return [...new Set(urls)];
  }

  private async connectClient(ctx: PluginLifecycleContext): Promise<{ client: Client; transport: SSEClientTransport; activeUrl: string }> {
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

  async handleStatus(_args: ToolArgs, ctx: PluginLifecycleContext): Promise<ToolResponse> {
    let transport: SSEClientTransport | null = null;
    try {
      const connected = await this.connectClient(ctx);
      transport = connected.transport;
      this.activeUrl = connected.activeUrl;
      const listed = (await this.withTimeout(
        connected.client.listTools(),
        8000,
        'tools/list timeout from remote Burp MCP server',
      )) as RemoteListToolsResult;
      const tools = Array.isArray(listed?.tools) ? listed.tools : [];

      return jsonResponse({
        success: true,
        endpoint: this.activeUrl,
        transport: 'sse',
        toolCount: tools.length,
        toolNames: tools.map((tool) => tool.name),
        serverVersion: connected.client.getServerVersion(),
        serverCapabilities: connected.client.getServerCapabilities(),
      });
    } catch (error) {
      return errorResponse('burp_mcp_sse_status', error, {
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

  async handleListTools(args: ToolArgs, ctx: PluginLifecycleContext): Promise<ToolResponse> {
    let transport: SSEClientTransport | null = null;
    try {
      const cursor = typeof args.cursor === 'string' ? args.cursor : undefined;
      const connected = await this.connectClient(ctx);
      transport = connected.transport;
      this.activeUrl = connected.activeUrl;

      const listed = (await this.withTimeout(
        connected.client.listTools({ cursor }),
        8000,
        'tools/list timeout from remote Burp MCP server',
      )) as RemoteListToolsResult;

      const tools = Array.isArray(listed?.tools) ? listed.tools : [];
      return jsonResponse({
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
      return errorResponse('burp_mcp_sse_list_tools', error, { endpoint: this.sseUrl });
    } finally {
      try {
        await transport?.close();
      } catch {
        // best effort
      }
    }
  }

  async handleCallTool(args: ToolArgs, ctx: PluginLifecycleContext): Promise<ToolResponse> {
    let transport: SSEClientTransport | null = null;
    const name = typeof args.name === 'string' ? args.name : '';
    if (!name) {
      return errorResponse('burp_mcp_sse_call_tool', new Error('name is required'));
    }

    const rawArguments = args.arguments;
    const toolArgs =
      rawArguments && typeof rawArguments === 'object' && !Array.isArray(rawArguments)
        ? (rawArguments as Record<string, unknown>)
        : {};

    try {
      const connected = await this.connectClient(ctx);
      transport = connected.transport;
      this.activeUrl = connected.activeUrl;
      const result = await this.withTimeout(
        connected.client.callTool({ name, arguments: toolArgs }),
        12000,
        `tools/call timeout for remote tool ${name}`,
      );

      return jsonResponse({
        success: true,
        endpoint: this.activeUrl,
        forwardedTool: name,
        result: safeParseToolContent(result),
      });
    } catch (error) {
      return errorResponse('burp_mcp_sse_call_tool', error, { endpoint: this.sseUrl, forwardedTool: name });
    } finally {
      try {
        await transport?.close();
      } catch {
        // best effort
      }
    }
  }
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

export default createExtension('io.github.vmoranv.burp-mcp-sse-call-tool', '0.1.0')
  .compatibleCore('>=0.1.0')
  .allowHost(['127.0.0.1', 'localhost', '::1'])
  .allowTool(['burp_mcp_sse_status', 'burp_mcp_sse_list_tools', 'burp_mcp_sse_call_tool'])
  .configDefault(`plugins.${PLUGIN_SLUG}.enabled`, true)
  .configDefault(`plugins.${PLUGIN_SLUG}.baseUrl`, 'http://127.0.0.1:9876')
  .metric([
    'burp_mcp_sse_status_calls_total',
    'burp_mcp_sse_list_tools_calls_total',
    'burp_mcp_sse_call_tool_calls_total',
  ])
  .tool(
    'burp_mcp_sse_status',
    'Check connectivity to Burp official MCP server over SSE and return tool catalog summary.',
    {},
    async (args, ctx) => {
      const sseUrl = ctx.getConfig(`plugins.${PLUGIN_SLUG}.baseUrl`, 'http://127.0.0.1:9876') as string;
      const authToken = process.env.BURP_MCP_AUTH_TOKEN;
      const handlers = new BurpMcpSseHandlers(sseUrl, authToken);
      return handlers.handleStatus(args, ctx);
    },
  )
  .tool(
    'burp_mcp_sse_list_tools',
    'List tools exposed by remote Burp MCP server over SSE.',
    {
      cursor: { type: 'string', description: 'Optional pagination cursor' },
    },
    async (args, ctx) => {
      const sseUrl = ctx.getConfig(`plugins.${PLUGIN_SLUG}.baseUrl`, 'http://127.0.0.1:9876') as string;
      const authToken = process.env.BURP_MCP_AUTH_TOKEN;
      const handlers = new BurpMcpSseHandlers(sseUrl, authToken);
      return handlers.handleListTools(args, ctx);
    },
  )
  .tool(
    'burp_mcp_sse_call_tool',
    'Call any remote tool exposed by Burp MCP server over SSE.',
    {
      name: { type: 'string', description: 'Remote tool name' },
      arguments: {
        type: 'object',
        additionalProperties: true,
        description: 'Arguments object forwarded to remote tool',
      },
    },
    async (args, ctx) => {
      const sseUrl = ctx.getConfig(`plugins.${PLUGIN_SLUG}.baseUrl`, 'http://127.0.0.1:9876') as string;
      const authToken = process.env.BURP_MCP_AUTH_TOKEN;
      const handlers = new BurpMcpSseHandlers(sseUrl, authToken);
      return handlers.handleCallTool(args, ctx);
    },
  )
  .onLoad((ctx) => {
    ctx.setRuntimeData('loadedAt', new Date().toISOString());
  })
  .onValidate((ctx: PluginLifecycleContext) => {
    const enabled = getPluginBooleanConfig(ctx, PLUGIN_SLUG, 'enabled', true);
    if (!enabled) return { valid: false, errors: ['Plugin disabled by config'] };
    return { valid: true, errors: [] };
  });
