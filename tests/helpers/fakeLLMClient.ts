// Canned-response LLM fake. Constructed with the exact text the test wants the
// reporter to receive. Records every call it sees so tests can assert on
// system prompt / user message contents.
//
// Lives under tests/ rather than src/: tsconfig compiles src/** with
// declaration: true into dist, so while this class sat in src/shared/ it was
// compiled and shipped into the build output despite having no production
// consumer.

import type {
  LLMClient,
  LLMCompleteOptions,
  LLMCompleteResult,
} from '../../src/shared/llmClient.js';

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
