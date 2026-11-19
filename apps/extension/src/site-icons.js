// Chrome's extension-local favicon service reads the profile cache. Only fixed
// RGBA pixels cross native messaging. Never fetch a URL supplied by a site.
const size = 16;

async function chromePixels(pageURL) {
  const source = new URL(chrome.runtime.getURL('/_favicon/'));
  source.searchParams.set('pageUrl', pageURL);
  source.searchParams.set('size', String(size));
  const response = await fetch(source);
  if (!response.ok) return null;
  const image = await createImageBitmap(await response.blob());
  try {
    const ctx = new OffscreenCanvas(size, size).getContext('2d');
    ctx.drawImage(image, 0, 0, size, size);
    return btoa(String.fromCharCode(...ctx.getImageData(0, 0, size, size).data));
  } finally { image.close(); }
}

export class SiteIconSearch {
  constructor(pageURL) {
    this.page = new URL(pageURL);
    this.visited = new Set();
    this.icons = new Map();
  }
  async collect(connection, items, assertCurrent) {
    const hosts = [...new Set(items.map(item => item.saved_host))].filter(host => !this.visited.has(host));
    if (!hosts.length) return;
    // Chrome returns its generic globe on a cache miss. Never persist it.
    this.missing ??= chromePixels('about:blank');
    const missing = await this.missing;
    const captures = await Promise.all(hosts.map(async host => {
      const url = new URL(this.page.origin);
      url.hostname = host;
      const pixels = await chromePixels(host === this.page.hostname ? this.page.href : url.href);
      return [host, pixels === missing ? null : pixels];
    }));
    await assertCurrent();
    const reply = await connection.request({ method: 'site_icons', captures: Object.fromEntries(captures) });
    if (reply.status !== 'site_icons') throw new Error('Unexpected site icon reply.');
    for (const host of hosts) this.visited.add(host);
    for (const [host, pixels] of Object.entries(reply.icons)) this.icons.set(host, pixels);
  }
}

export function siteIcon(pixels) {
  const bytes = Uint8ClampedArray.from(atob(pixels), character => character.charCodeAt(0));
  const canvas = document.createElement('canvas');
  canvas.width = canvas.height = size;
  canvas.className = 'site-icon';
  canvas.setAttribute('aria-hidden', 'true');
  canvas.getContext('2d').putImageData(new ImageData(bytes, size, size), 0, 0);
  return canvas;
}
