/**
 * Spawn the witness as a real child process, the way Fly runs it.
 *
 * In-process tests cannot answer "does a restored database come back up as a
 * working service", because they never restart anything. This does.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { join } from 'node:path';

export interface LiveWitness {
  url: string;
  port: number;
  pubkeyPem: string;
  stdout: string[];
  proc: ChildProcess;
  stop: () => Promise<void>;
}

export async function spawnWitness(env: Record<string, string>): Promise<LiveWitness> {
  const proc = spawn(
    join(process.cwd(), 'node_modules', '.bin', 'tsx'),
    [join(process.cwd(), 'src', 'index.ts'), 'serve'],
    { env: { ...process.env, PORT: '0', ...env }, stdio: ['ignore', 'pipe', 'pipe'] },
  );

  const lines: string[] = [];
  let port = 0;
  let pubkeyPem = '';
  let stderr = '';
  proc.stderr?.on('data', (d: Buffer) => { stderr += d.toString(); });

  await new Promise<void>((resolveReady, reject) => {
    const timer = setTimeout(() => reject(new Error(`witness did not start in 30s. stderr:\n${stderr}`)), 30_000);
    let buffer = '';
    proc.stdout?.on('data', (d: Buffer) => {
      buffer += d.toString();
      const parts = buffer.split('\n');
      buffer = parts.pop() ?? '';
      for (const line of parts) {
        if (!line.trim()) continue;
        lines.push(line);
        try {
          const e = JSON.parse(line) as { msg?: string; port?: number; pem?: string };
          if (e.msg === 'witness listening' && e.port) port = e.port;
          if (e.msg === 'witness public key' && e.pem) pubkeyPem = e.pem;
        } catch { /* not our JSON */ }
        if (port && pubkeyPem) { clearTimeout(timer); resolveReady(); return; }
      }
    });
    proc.on('exit', (code) => { clearTimeout(timer); reject(new Error(`witness exited ${code}. stderr:\n${stderr}`)); });
  });

  return {
    url: `http://127.0.0.1:${port}`, port, pubkeyPem, stdout: lines, proc,
    stop: () => new Promise<void>((r) => {
      if (proc.exitCode !== null) { r(); return; }
      proc.once('exit', () => r());
      proc.kill('SIGTERM');
      setTimeout(() => { proc.kill('SIGKILL'); r(); }, 5000).unref();
    }),
  };
}
