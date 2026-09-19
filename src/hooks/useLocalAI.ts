import { useState, useCallback, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';

export function useLocalAI() {
  const [isReady, setIsReady] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [statusText, setStatusText] = useState('Offline');
  const [error, setError] = useState<string | null>(null);
  const initAttempted = useRef(false);

  const initRuntime = useCallback(async () => {
    if (initAttempted.current || isReady) return;
    initAttempted.current = true;

    try {
      setIsLoading(true);
      setError(null);
      
      setStatusText('Bootstrapping inference runtime & model weights...');
      await invoke('ensure_inference_runtime');

      setStatusText('Spawning local llama-server...');
      await invoke<number>('start_inference_server');

      setStatusText('Waiting for model to load into memory...');
      await waitForServerReady();

      setIsReady(true);
      setStatusText('Local AI Ready (Qwen2.5-0.5B)');
    } catch (err: any) {
      setError(typeof err === 'string' ? err : err.message || 'Initialization failed');
      setStatusText('Error');
      initAttempted.current = false;
    } finally {
      setIsLoading(false);
    }
  }, [isReady]);

  const queryAI = useCallback(async (prompt: string, systemPrompt?: string) => {
    if (!isReady) {
      throw new Error('Local AI runtime not initialized yet.');
    }

    const messages = [];
    if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
    messages.push({ role: 'user', content: prompt });

    const res = await fetch('http://127.0.0.1:8080/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messages,
        temperature: 0.1,
      }),
    });

    if (!res.ok) {
      throw new Error(`Inference request failed: ${res.statusText}`);
    }

    const data = await res.json();
    return data.choices[0].message.content as string;
  }, [isReady]);

  return { isReady, isLoading, statusText, error, initRuntime, queryAI };
}

async function waitForServerReady(retries = 30, delayMs = 500) {
  for (let i = 0; i < retries; i++) {
    try {
      const res = await fetch('http://127.0.0.1:8080/v1/models');
      if (res.ok) return;
    } catch {
      // Ignore connection refused while server boots
    }
    await new Promise((r) => setTimeout(r, delayMs));
  }
  throw new Error('Timed out waiting for local inference server to accept connections.');
}
