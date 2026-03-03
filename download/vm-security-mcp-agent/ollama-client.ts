/**
 * Local LLM Client using Ollama
 * Supports Llama 3, Mistral, and other open-source models running locally
 */

export interface OllamaConfig {
  baseUrl: string;
  model: string;
  temperature?: number;
  topP?: number;
  topK?: number;
  numPredict?: number;
  contextWindow?: number;
}

export interface OllamaGenerateRequest {
  model: string;
  prompt: string;
  system?: string;
  template?: string;
  context?: number[];
  stream?: boolean;
  raw?: boolean;
  format?: 'json';
  options?: {
    temperature?: number;
    top_p?: number;
    top_k?: number;
    num_predict?: number;
    num_ctx?: number;
    seed?: number;
  };
}

export interface OllamaGenerateResponse {
  model: string;
  created_at: string;
  response: string;
  done: boolean;
  context?: number[];
  total_duration?: number;
  load_duration?: number;
  prompt_eval_count?: number;
  prompt_eval_duration?: number;
  eval_count?: number;
  eval_duration?: number;
}

export interface OllamaModel {
  name: string;
  modified_at: string;
  size: number;
  digest: string;
  details?: {
    format: string;
    family: string;
    parameter_size: string;
    quantization_level: string;
  };
}

export interface OllamaListModelResponse {
  models: OllamaModel[];
}

/**
 * Ollama Client for Local LLM Inference
 */
export class OllamaClient {
  private config: OllamaConfig;

  constructor(config: Partial<OllamaConfig> = {}) {
    this.config = {
      baseUrl: config.baseUrl || process.env.OLLAMA_BASE_URL || 'http://localhost:11434',
      model: config.model || process.env.OLLAMA_MODEL || 'llama3.2',
      temperature: config.temperature ?? 0.3,
      topP: config.topP ?? 0.9,
      topK: config.topK ?? 40,
      numPredict: config.numPredict ?? 4096,
      contextWindow: config.contextWindow ?? 8192,
    };
  }

  /**
   * Check if Ollama server is running
   */
  async isServerRunning(): Promise<boolean> {
    try {
      const response = await fetch(`${this.config.baseUrl}/api/tags`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * List available models
   */
  async listModels(): Promise<OllamaModel[]> {
    try {
      const response = await fetch(`${this.config.baseUrl}/api/tags`, {
        method: 'GET',
      });
      
      if (!response.ok) {
        throw new Error(`Failed to list models: ${response.statusText}`);
      }

      const data: OllamaListModelResponse = await response.json();
      return data.models || [];
    } catch (error) {
      console.error('Error listing Ollama models:', error);
      return [];
    }
  }

  /**
   * Generate completion using local LLM
   */
  async generate(
    prompt: string,
    systemPrompt?: string,
    options: Partial<OllamaConfig> = {}
  ): Promise<string> {
    const request: OllamaGenerateRequest = {
      model: options.model || this.config.model,
      prompt,
      system: systemPrompt,
      stream: false,
      format: 'json',
      options: {
        temperature: options.temperature ?? this.config.temperature,
        top_p: options.topP ?? this.config.topP,
        top_k: options.topK ?? this.config.topK,
        num_predict: options.numPredict ?? this.config.numPredict,
        num_ctx: options.contextWindow ?? this.config.contextWindow,
      },
    };

    try {
      const response = await fetch(`${this.config.baseUrl}/api/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
        signal: AbortSignal.timeout(300000), // 5 minute timeout
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Ollama API error: ${response.statusText} - ${errorText}`);
      }

      const data: OllamaGenerateResponse = await response.json();
      return data.response;
    } catch (error) {
      console.error('Error generating with Ollama:', error);
      throw error;
    }
  }

  /**
   * Generate with chat-style interface
   */
  async chat(
    messages: Array<{ role: 'system' | 'user' | 'assistant'; content: string }>,
    options: Partial<OllamaConfig> = {}
  ): Promise<string> {
    // Convert chat messages to a single prompt
    let systemPrompt = '';
    let conversationPrompt = '';

    for (const msg of messages) {
      if (msg.role === 'system') {
        systemPrompt = msg.content;
      } else if (msg.role === 'user') {
        conversationPrompt += `\n<|user|>\n${msg.content}\n</user>\n`;
      } else if (msg.role === 'assistant') {
        conversationPrompt += `\n<|assistant|]\n${msg.content}\n</assistant>\n`;
      }
    }

    conversationPrompt += '\n<|assistant|]\n';

    return this.generate(conversationPrompt, systemPrompt, options);
  }

  /**
   * Generate JSON response
   */
  async generateJSON<T>(
    prompt: string,
    systemPrompt?: string,
    options: Partial<OllamaConfig> = {}
  ): Promise<T> {
    const jsonSystemPrompt = `${systemPrompt || ''}\n\nYou MUST respond with valid JSON only. No markdown, no code blocks, just pure JSON.`;
    
    const response = await this.generate(prompt, jsonSystemPrompt, options);
    
    try {
      // Try to extract JSON from the response
      const jsonMatch = response.match(/\{[\s\S]*\}|\[[\s\S]*\]/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]) as T;
      }
      throw new Error('No valid JSON found in response');
    } catch (error) {
      console.error('Error parsing JSON response:', error);
      console.error('Raw response:', response);
      throw new Error(`Failed to parse JSON response: ${error}`);
    }
  }

  /**
   * Pull a model if not available
   */
  async pullModel(model: string): Promise<boolean> {
    try {
      const response = await fetch(`${this.config.baseUrl}/api/pull`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name: model, stream: false }),
        signal: AbortSignal.timeout(600000), // 10 minute timeout for pulling
      });

      return response.ok;
    } catch (error) {
      console.error('Error pulling model:', error);
      return false;
    }
  }

  /**
   * Get current configuration
   */
  getConfig(): OllamaConfig {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  setConfig(config: Partial<OllamaConfig>): void {
    this.config = { ...this.config, ...config };
  }
}

// Recommended models for security analysis
export const RECOMMENDED_MODELS = {
  'llama3.2': {
    name: 'Llama 3.2',
    description: 'Latest Llama model with excellent reasoning capabilities',
    minRam: '8GB',
    recommended: true,
  },
  'llama3.1': {
    name: 'Llama 3.1',
    description: 'Powerful model for complex analysis',
    minRam: '16GB',
    recommended: true,
  },
  'mistral': {
    name: 'Mistral',
    description: 'Fast and efficient for security analysis',
    minRam: '8GB',
    recommended: true,
  },
  'codellama': {
    name: 'Code Llama',
    description: 'Specialized for code analysis and infrastructure',
    minRam: '8GB',
    recommended: false,
  },
  'mixtral': {
    name: 'Mixtral 8x7B',
    description: 'MoE model with excellent analysis capabilities',
    minRam: '24GB',
    recommended: true,
  },
};

// Export default client instance
export const ollamaClient = new OllamaClient();
