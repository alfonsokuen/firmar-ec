import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Guarda de los ficheros de workflow (Gitea y GitHub).
 *
 * Nace de un fallo real (2026-09-09): al editar `.gitea/workflows/deploy.yml`
 * se colo un **CR suelto** dentro de un `tr -d '…'`. YAML trata el CR como un
 * salto de linea, asi que partia la linea en dos y el resto quedaba en columna
 * 1 —fuera del bloque `run: |`— y el documento dejaba de parsear.
 *
 * Lo caro no fue el error, fue el silencio: **Gitea ignora un workflow
 * invalido sin fallar el push**. El fichero llego a `main`, dejo de crearse
 * ningun run, y el sintoma («el deploy no se dispara») apunta al runner, no al
 * YAML — se perdio un buen rato buscando en el sitio equivocado, hasta que el
 * log de Gitea confeso `ignore invalid workflow "deploy.yml"`.
 *
 * No hay parser YAML resoluble en este monorepo, y no se añade una dependencia
 * por esto (KISS). Lo que se afirma son los bytes que rompen el parser en
 * silencio y que ninguna revision humana ve: CR sueltos y tabuladores. No es
 * un validador de esquema; es la red contra ESTE modo de fallo.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..', '..');
const WORKFLOW_DIRS = [join(REPO, '.gitea', 'workflows'), join(REPO, '.github', 'workflows')];

const CR = '\r';
const TAB = '\t';

function workflowFiles(): { path: string; name: string }[] {
  const out: { path: string; name: string }[] = [];
  for (const dir of WORKFLOW_DIRS) {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue; // el repo puede no tener uno de los dos
    }
    for (const f of entries) {
      if (f.endsWith('.yml') || f.endsWith('.yaml')) out.push({ path: join(dir, f), name: f });
    }
  }
  return out;
}

describe('workflows — bytes que rompen el parser en silencio', () => {
  const files = workflowFiles();

  it('encuentra los workflows (si no, esta prueba no afirma nada)', () => {
    expect(files.length).toBeGreaterThan(0);
    expect(files.map((f) => f.name)).toContain('deploy.yml');
  });

  for (const { path, name } of files) {
    it(`${name} no lleva ningun CR`, () => {
      const raw = readFileSync(path, 'utf8');
      // Vale tanto para CRLF (que confunde a los runners POSIX) como para un CR
      // suelto dentro de una cadena, que es lo que rompio deploy.yml.
      const lineas = raw
        .split('\n')
        .map((l, i) => ({ n: i + 1, l }))
        .filter((x) => x.l.includes(CR));
      expect(lineas.map((x) => x.n)).toEqual([]);
    });

    it(`${name} no lleva tabuladores (YAML los prohibe para indentar)`, () => {
      const raw = readFileSync(path, 'utf8');
      const lineas = raw
        .split('\n')
        .map((l, i) => ({ n: i + 1, l }))
        .filter((x) => x.l.includes(TAB));
      expect(lineas.map((x) => x.n)).toEqual([]);
    });
  }
});
