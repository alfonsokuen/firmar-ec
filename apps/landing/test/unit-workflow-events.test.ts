import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const workflow = readFileSync(join(repo, '.gitea/workflows/unit.yml'), 'utf8');
// Ejecutar el primer bloque real del workflow, sin copiar su lógica al test.
const match = workflow.match(/        run: \|\n((?:\n|          [^\n]*\n)+)/);
if (!match) throw new Error('No se encontró el paso de validación del workflow unitario');
const script = match[1].replace(/^          /gm, '');
const bash = process.env.TEST_BASH ?? (process.platform === 'win32'
  ? `${process.env.ProgramFiles}/Git/bin/bash.exe` : 'bash');
const sha = 'a'.repeat(40);

function run(event: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), 'unit-event-'));
  const workspace = join(dir, 'workspace');
  const envFile = join(dir, 'github-env');
  mkdirSync(workspace);
  writeFileSync(envFile, '');
  try {
    const result = spawnSync(bash, ['--noprofile', '--norc', '-s'], {
      input: script, encoding: 'utf8', timeout: 10_000,
      env: {
        ...process.env, EVENT_NAME: '', PUSH_SHA: '', PUSH_REF: '',
        HEAD_SHA: '', HEAD_REF: '', HEAD_REPO: '', THIS_REPO: 'alfonso/firmar-ec',
        GITHUB_WORKSPACE: workspace.replaceAll('\\', '/'),
        GITHUB_ENV: envFile.replaceAll('\\', '/'), ...event,
      },
    });
    if (result.error) throw result.error;
    return { status: result.status, error: result.stderr, env: readFileSync(envFile, 'utf8') };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('unit workflow — eventos reales', () => {
  it('acepta push a main sin campos pull_request y exporta el commit exacto', () => {
    const r = run({ EVENT_NAME: 'push', PUSH_SHA: sha, PUSH_REF: 'main' });
    expect(r.status, r.error).toBe(0);
    expect(r.env).toContain(`HEAD_SHA=${sha}\n`);
    expect(r.env).toContain('HEAD_REF=main\n');
  });
  it('acepta un PR propio', () => {
    expect(run({ EVENT_NAME: 'pull_request', HEAD_SHA: sha, HEAD_REF: 'docs/autor',
      HEAD_REPO: 'alfonso/firmar-ec' }).status).toBe(0);
  });
  it('rechaza forks aunque existan campos del evento push', () => {
    const r = run({ EVENT_NAME: 'pull_request', HEAD_SHA: sha, HEAD_REF: 'main',
      HEAD_REPO: 'externo/fork', PUSH_SHA: sha, PUSH_REF: 'main' });
    expect(r.status).not.toBe(0);
    expect(r.env).toBe('');
  });
  it('rechaza PR sin procedencia', () => {
    expect(run({ EVENT_NAME: 'pull_request', HEAD_SHA: sha, HEAD_REF: 'main' }).status).not.toBe(0);
  });
  it('rechaza push fuera de main', () => {
    expect(run({ EVENT_NAME: 'push', PUSH_SHA: sha, PUSH_REF: 'feature' }).status).not.toBe(0);
  });
  it('rechaza push sin SHA', () => {
    expect(run({ EVENT_NAME: 'push', PUSH_REF: 'main' }).status).not.toBe(0);
  });
  it('rechaza eventos no soportados', () => {
    expect(run({ EVENT_NAME: 'workflow_dispatch', HEAD_SHA: sha, HEAD_REF: 'main',
      HEAD_REPO: 'alfonso/firmar-ec' }).status).not.toBe(0);
  });
});
