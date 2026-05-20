// Thin interface around the Anthropic Messages API.
//
// Two callers in the wider system are sanctioned to invoke an LLM (per
// CLAUDE.md hard rules): the Reporter's PR-description composer (Slice 11)
// and a future Hunter unstructured-source extraction step. Both go through
// this interface so that:
//
//   * production code constructs `AnthropicLLMClient` (which talks to the
//     real API and requires ANTHROPIC_API_KEY);
//   * tests construct `FakeLLMClient` with a canned response, so CI never
//     hits the real API and costs zero per run.
//
// The shape is deliberately narrower than the SDK's `messages.create`:
// no streaming, no multi-turn, no tool use, no image content. Reporter
// needs exactly one synchronous text completion per call, and widening the
// surface area would make the fake harder to write convincingly.

import Anthropic from '@anthropic-ai/sdk';

export interface LLMCompleteOptions {
  model: string;
  systemPrompt: string;
  userMessage: string;
  maxTokens: number;
}

export interface LLMCompleteResult {
  text: string;
  inputTokens: number;
  outputTokens: number;
}

export interface LLMClient {
  complete(opts: LLMCompleteOptions): Promise<LLMCompleteResult>;
}

// Minimal slice of `Anthropic` we actually depend on. Letting callers (or
// the AnthropicLLMClient's own constructor) inject anything matching this
// shape keeps the unit test for the wrapper itself decoupled from a real
// API key — only the *real* client construction path requires the env var.
export interface AnthropicMessagesAPI {
  create(params: {
    model: string;
    max_tokens: number;
    system: string;
    messages: Array<{ role: 'user'; content: string }>;
  }): Promise<{
    content: Array<{ type: string; text?: string }>;
    usage: { input_tokens: number; output_tokens: number };
  }>;
}

export interface AnthropicSDKLike {
  messages: AnthropicMessagesAPI;
}

// Real production client. Calls Anthropic, prints a token-cost log line on
// stdout in the shape:
//
//   [llm-cost] input=N output=M model=<model-id>
//
// Slice 12's workflow can grep for this line to track cost drift over time.
export class AnthropicLLMClient implements LLMClient {
  private readonly sdk: AnthropicSDKLike;

  constructor(sdk?: AnthropicSDKLike) {
    if (sdk) {
      this.sdk = sdk;
      return;
    }
    const apiKey = process.env['ANTHROPIC_API_KEY'];
    if (!apiKey) {
      throw new Error(
        'AnthropicLLMClient: ANTHROPIC_API_KEY environment variable is not set. ' +
          'Add it to your .env file for local runs, or to GitHub Actions secrets for CI.',
      );
    }
    this.sdk = new Anthropic({ apiKey }) as unknown as AnthropicSDKLike;
  }

  async complete(opts: LLMCompleteOptions): Promise<LLMCompleteResult> {
    const response = await this.sdk.messages.create({
      model: opts.model,
      max_tokens: opts.maxTokens,
      system: opts.systemPrompt,
      messages: [{ role: 'user', content: opts.userMessage }],
    });

    // Concatenate the text blocks. The Messages API may emit multiple text
    // blocks (e.g. when thinking is enabled — we don't enable it, but the
    // join is a no-op when there's only one block, and a safe default if
    // the response shape ever expands).
    const text = response.content
      .filter((block) => block.type === 'text')
      .map((block) => block.text ?? '')
      .join('');

    const inputTokens = response.usage.input_tokens;
    const outputTokens = response.usage.output_tokens;

    // eslint-disable-next-line no-console
    console.log(
      `[llm-cost] input=${inputTokens} output=${outputTokens} model=${opts.model}`,
    );

    return { text, inputTokens, outputTokens };
  }
}

// Canned-response fake. Constructed with the exact text the test wants the
// reporter to receive. Records every call it sees so tests can assert on
// system prompt / user message contents.
export class FakeLLMClient implements LLMClient {
  public readonly calls: LLMCompleteOptions[] = [];
  private readonly cannedResponse: string;
  private readonly inputTokens: number;
  private readonly outputTokens: number;

  constructor(cannedResponse: string, tokenCounts?: { input: number; output: number }) {
    this.cannedResponse = cannedResponse;
    this.inputTokens = tokenCounts?.input ?? 0;
    this.outputTokens = tokenCounts?.output ?? 0;
  }

  async complete(opts: LLMCompleteOptions): Promise<LLMCompleteResult> {
    this.calls.push(opts);
    return {
      text: this.cannedResponse,
      inputTokens: this.inputTokens,
      outputTokens: this.outputTokens,
    };
  }
}
