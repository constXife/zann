// Shared packaged vector, independent of platform font glyph coverage.
export function keyIcon(document) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  for (const [name, value] of Object.entries({ viewBox: '0 0 24 24', width: '16', height: '16', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.8', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' })) svg.setAttribute(name, value);
  const circle = document.createElementNS(ns, 'circle');
  circle.setAttribute('cx', '7'); circle.setAttribute('cy', '16'); circle.setAttribute('r', '4');
  const teeth = document.createElementNS(ns, 'path'); teeth.setAttribute('d', 'M10 13 20 3l2 2-3 3-2-2M15 8l2 2');
  svg.append(circle, teeth); return svg;
}
