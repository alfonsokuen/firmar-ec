import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, test } from 'vitest';

/**
 * deploy-guard.test.ts — scripts/_deploy-guard.sh only lets a manual deploy
 * ship a commit that is already on <remote>/main, from a clean tree.
 *
 * 2026-09-24: the landing ran 0.7.9-utm-ad4ff5a, built from GitHub main,
 * while Gitea main (what the CI deploys) was 10 commits behind; the next push
 * there would have reverted it. Each case runs the real guard in a throwaway
 * repo whose "gitea" remote is a local bare repo.
 */

const GUARD = resolve(__dirname, '../../../scripts/_deploy-guard.sh');

function git(cwd: string, ...args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
}

function repoWithRemote(): { work: string } {
  const root = mkdtempSync(join(tmpdir(), 'deploy-guard-'));
  const bare = join(root, 'remote.git');
  const work = join(root, 'work');
  git(root, 'init', '-q', '--bare', bare);
  git(root, 'init', '-q', '-b', 'main', work);
  git(work, 'config', 'user.email', 'guard@test.invalid');
  git(work, 'config', 'user.name', 'guard test');
  git(work, 'config', 'commit.gpgsign', 'false');
  writeFileSync(join(work, 'a.txt'), 'a\n');
  git(work, 'add', '.');
  git(work, 'commit', '-q', '-m', 'on main');
  git(work, 'remote', 'add', 'gitea', bare);
  git(work, 'push', '-q', 'gitea', 'main');
  return { work };
}

function runGuard(cwd: string, env: Record<string, string> = {}) {
  const r = spawnSync('bash', ['-c', `. "${GUARD.replace(/\\/g, '/')}" && deploy_guard_on_main`], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, ALLOW_OFF_MAIN_DEPLOY: '', ...env },
  });
  return { code: r.status, err: r.stderr };
}

describe('deploy guard', () => {
  test('a commit already on gitea/main, clean tree → allowed', () => {
    const { work } = repoWithRemote();
    expect(runGuard(work).code).toBe(0);
  });

  test('a commit that is not on gitea/main (the 2026-09-24 drift) → refused', () => {
    const { work } = repoWithRemote();
    git(work, 'switch', '-q', '-c', 'feature');
    writeFileSync(join(work, 'b.txt'), 'b\n');
    git(work, 'add', '.');
    git(work, 'commit', '-q', '-m', 'off main');
    const r = runGuard(work);
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/RECHAZADO: .* no es la punta de gitea\/main/);
  });

  test('uncommitted changes (they would be tarred and shipped) → refused', () => {
    const { work } = repoWithRemote();
    writeFileSync(join(work, 'a.txt'), 'changed\n');
    const r = runGuard(work);
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/sin commitear/);
  });

  test('explicit emergency bypass → allowed, and it says so', () => {
    const { work } = repoWithRemote();
    git(work, 'switch', '-q', '-c', 'hotfix');
    writeFileSync(join(work, 'c.txt'), 'c\n');
    git(work, 'add', '.');
    git(work, 'commit', '-q', '-m', 'hotfix');
    const r = runGuard(work, { ALLOW_OFF_MAIN_DEPLOY: '1' });
    expect(r.code).toBe(0);
    expect(r.err).toMatch(/AVISO: ALLOW_OFF_MAIN_DEPLOY=1/);
  });

  test('unreachable remote → refused (fails closed)', () => {
    const { work } = repoWithRemote();
    git(work, 'remote', 'set-url', 'gitea', join(work, 'no-such-remote.git'));
    expect(runGuard(work).code).toBe(1);
  });

  test('an older commit of main (not its tip) -> refused: the CI would ship the tip', () => {
    const { work } = repoWithRemote();
    const old = git(work, 'rev-parse', 'HEAD');
    writeFileSync(join(work, 'b.txt'), 'b\n');
    git(work, 'add', '.');
    git(work, 'commit', '-q', '-m', 'newer on main');
    git(work, 'push', '-q', 'gitea', 'main');
    git(work, 'checkout', '-q', old);
    const r = runGuard(work);
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/punta de gitea\/main/);
  });

  test('bypass persisted in .deploy.env -> refused even when set', () => {
    const { work } = repoWithRemote();
    git(work, 'switch', '-q', '-c', 'feature');
    writeFileSync(join(work, 'b.txt'), 'b\n');
    writeFileSync(join(work, '.gitignore'), '.deploy.env\n');
    git(work, 'add', '.');
    git(work, 'commit', '-q', '-m', 'off main');
    writeFileSync(join(work, '.deploy.env'), 'ALLOW_OFF_MAIN_DEPLOY=1\n');
    const r = runGuard(work, { ALLOW_OFF_MAIN_DEPLOY: '1' });
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/\.deploy\.env/);
  });

  test('another remote cannot be swapped in (DEPLOY_SOURCE_REMOTE is ignored)', () => {
    const { work } = repoWithRemote();
    git(work, 'switch', '-q', '-c', 'feature');
    writeFileSync(join(work, 'b.txt'), 'b\n');
    git(work, 'add', '.');
    git(work, 'commit', '-q', '-m', 'only on the mirror');
    git(work, 'remote', 'add', 'mirror', join(work, '..', 'remote.git'));
    git(work, 'push', '-q', 'mirror', 'HEAD:refs/heads/other');
    const r = runGuard(work, { DEPLOY_SOURCE_REMOTE: 'mirror', DEPLOY_SOURCE_BRANCH: 'other' });
    expect(r.code).toBe(1);
  });
});

describe('deploy guard: the bypass cannot come from a sourced env file (Codex)', () => {
  const offMain = () => {
    const { work } = repoWithRemote();
    git(work, 'switch', '-q', '-c', 'feature');
    writeFileSync(join(work, 'b.txt'), 'b\n');
    git(work, 'add', '.');
    git(work, 'commit', '-q', '-m', 'off main');
    return work;
  };
  // Mirrors the deploy scripts: guard sourced first, then the env file, then the check.
  const runWithEnvFile = (cwd: string, envLines: string) => {
    const envPath = join(cwd, '..', 'deploy.env.test');
    writeFileSync(envPath, envLines);
    const g = GUARD.replace(/\\/g, '/');
    const e = envPath.replace(/\\/g, '/');
    const r = spawnSync('bash', ['-c', `set -e; . "${g}"; . "${e}"; deploy_guard_on_main`], {
      cwd,
      encoding: 'utf8',
      env: { ...process.env, ALLOW_OFF_MAIN_DEPLOY: '' },
    });
    return r.status;
  };

  for (const line of [
    'export "ALLOW_OFF_MAIN_DEPLOY=1"',
    'declare -x ALLOW_OFF_MAIN_DEPLOY=1',
    'ALLOW_OFF_MAIN_DEPLOY=1',
  ]) {
    test(`env file with \`${line}\` -> refused`, () => {
      expect(runWithEnvFile(offMain(), `${line}\n`)).not.toBe(0);
    });
  }
});
