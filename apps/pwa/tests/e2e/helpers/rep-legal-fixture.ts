/**
 * rep-legal-fixture.ts — the identity published by the generated
 * legal-representative .p12, shared by the generator and the assertions.
 *
 * One source of truth on purpose: if the fixture said one thing and the spec
 * asserted another literal, the spec could keep passing while rendering the
 * wrong value (or keep failing after a deliberate change). The generator
 * writes exactly these attributes; the spec reads exactly these attributes.
 *
 * Every value is INVENTED. A real legal-representative certificate carries a
 * living person's cédula and a real company's RUC, and none may enter this
 * repository. `1700000001` passes the mod-10 check digit and belongs to nobody.
 *
 * @see apps/pwa/tests/e2e/global-setup.ts (writes the .p12)
 * @see apps/pwa/tests/e2e/validar-certificado-representante-legal.spec.ts
 */

/** Suffix → value, beneath the ACE's private arc. */
export const E2E_REP_LEGAL_ATTRS: Readonly<Record<string, string>> = {
  1: '1700000001', // cédula
  2: 'PRUEBA', // nombres
  3: 'APELLIDO', // primer apellido
  4: 'SEGUNDO', // segundo apellido
  5: 'REPRESENTANTE LEGAL', // cargo
  10: 'EMPRESA DEMO E2E S.A.S.', // razón social
  11: '1791234567001', // RUC de la EMPRESA (no el del titular)
};

export const E2E_REP_LEGAL_CN = 'PRUEBA E2E REPRESENTANTE';
