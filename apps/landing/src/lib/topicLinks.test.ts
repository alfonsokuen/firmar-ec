import { describe, expect, it } from 'vitest';
import { selectTopicLinks } from './topicLinks.ts';

const link = { href: '/respuestas/firmar/', anchor: 'Cómo firmar' };
const routes = new Set(['/respuestas/firmar/']);

describe('selectTopicLinks', () => {
  it('selecciona los enlaces de la home sin confundirlos con otras rutas', () => {
    const homeLink = { href: '/', anchor: 'Inicio' };
    const data = { '/': [link], '/en/': [homeLink] };
    const knownRoutes = new Set([...routes, '/']);

    expect(selectTopicLinks(data, '/', knownRoutes)).toEqual([link]);
    expect(selectTopicLinks(data, '/en/', knownRoutes)).toEqual([homeLink]);
    expect(selectTopicLinks(data, '/sin-entrada/', knownRoutes)).toEqual([]);
    expect(selectTopicLinks({}, '/', knownRoutes)).toEqual([]);
  });

  it.each(['/pilar', '/pilar/'])('normaliza la ruta actual %s', (path) => {
    expect(selectTopicLinks({ '/pilar/': [link] }, path, routes)).toEqual([link]);
    expect(selectTopicLinks({ '/pilar': [link] }, path, routes)).toEqual([link]);
  });

  it('no devuelve enlaces sin entrada o con entrada vacía', () => {
    expect(selectTopicLinks({}, '/pilar/', routes)).toEqual([]);
    expect(selectTopicLinks({ '/pilar/': [] }, '/pilar/', routes)).toEqual([]);
  });

  it.each([
    'https://externo.test/guia/',
    'https://firmar.ec/respuestas/firmar/',
    '//externo.test/guia/',
    '/\\externo.test/guia/',
    '/\n/externo.test/guia/',
    'javascript:alert(1)',
    'respuestas/firmar/',
    '/no-existe/',
  ])('descarta el destino inválido %j', (href) => {
    expect(selectTopicLinks({ '/pilar/': [{ ...link, href }, link] }, '/pilar/', routes)).toEqual([
      link,
    ]);
  });

  it('acepta destinos existentes sin barra final y con fragmento o query', () => {
    const links = [
      { ...link, href: '/respuestas/firmar' },
      { ...link, href: '/respuestas/firmar/?ref=pilar#pasos' },
    ];
    expect(selectTopicLinks({ '/pilar/': links }, '/pilar/', routes)).toEqual(links);
  });

  it('ignora datos malformados y anchors vacíos', () => {
    for (const data of [null, [], { '/pilar/': null }, { '/pilar/': {} }]) {
      expect(selectTopicLinks(data, '/pilar/', routes)).toEqual([]);
    }
    expect(
      selectTopicLinks(
        { '/pilar/': [null, {}, { ...link, anchor: ' ' }, link] },
        '/pilar/',
        routes,
      ),
    ).toEqual([link]);
  });
});
