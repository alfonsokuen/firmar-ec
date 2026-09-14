import { type PDFDict, type PDFDocument, PDFString } from 'pdf-lib';
import type { VisibleSigInput } from './visibleSig.js';

type Rect = [number, number, number, number];

/** Map the painted QR's local rectangle through the signature appearance rotation. */
export function createQrLink(
  doc: PDFDocument,
  spec: VisibleSigInput,
  url: string,
  localRect: Rect,
): PDFDict {
  const rotate = spec.rotate ?? 0;
  const swapped = rotate === 90 || rotate === 270;
  const width = swapped ? spec.height : spec.width;
  const height = swapped ? spec.width : spec.height;
  // The appearance is clipped to its BBox. Do not put a link outside the stamp.
  const [x1, y1, x2, y2] = localRect.map((n, i) =>
    Math.max(0, Math.min(n, i % 2 === 0 ? width : height)),
  ) as Rect;
  const points = [
    [x1, y1],
    [x2, y2],
  ].map(([x, y]) => {
    const u = x!;
    const v = y!;
    switch (rotate) {
      case 90:
        return [v, width - u];
      case 180:
        return [width - u, height - v];
      case 270:
        return [height - v, u];
      default:
        return [u, v];
    }
  });
  const rect = [
    spec.x + Math.min(points[0]![0]!, points[1]![0]!),
    spec.y + Math.min(points[0]![1]!, points[1]![1]!),
    spec.x + Math.max(points[0]![0]!, points[1]![0]!),
    spec.y + Math.max(points[0]![1]!, points[1]![1]!),
  ];
  return doc.context.obj({
    Type: 'Annot',
    Subtype: 'Link',
    Rect: rect,
    Border: [0, 0, 0],
    H: 'N',
    Contents: PDFString.of('Verificar este PDF en firmar.ec'),
    A: { S: 'URI', URI: PDFString.of(url) },
  });
}
