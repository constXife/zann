import { spawnSync } from 'node:child_process';
import { cp, mkdir, rm, writeFile } from 'node:fs/promises';
import { pageFields } from './src/fields.js';
import { installInline } from './src/inline-content.js';
import { keyIcon } from './src/key-icon.js';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../..');
function run(command, args, env = {}) {
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit', env: { ...process.env, ...env } });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} failed (${result.status})`);
}
// CLI version is pinned to the wasm-bindgen crate in Cargo.lock.
const version = spawnSync('wasm-bindgen', ['--version'], { encoding: 'utf8' });
if (version.error) throw version.error;
if (version.stdout?.trim() !== 'wasm-bindgen 0.2.106') throw new Error('Install wasm-bindgen-cli 0.2.106');
run('cargo', ['build', '--locked', '-p', 'zann-browser', '--target', 'wasm32-unknown-unknown', '--release'], {
  CARGO_TARGET_DIR: path.join(root, 'target/browser'),
  CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS: '--cfg getrandom_backend="wasm_js"'
});
const dist = path.join(here, 'dist');
await rm(dist, { recursive: true, force: true });
await mkdir(path.join(dist, 'wasm'), { recursive: true });
run('wasm-bindgen', [path.join(root, 'target/browser/wasm32-unknown-unknown/release/zann_browser.wasm'), '--target', 'web', '--no-typescript', '--out-dir', path.join(dist, 'wasm')]);
await cp(path.join(here, 'src'), dist, { recursive: true });
// Packaged classic content script; no runtime eval/import or page-world bridge.
await writeFile(path.join(dist, 'content.js'), `(()=>{${pageFields.toString()}\n${keyIcon.toString()}\n(${installInline.toString()})(pageFields, keyIcon);})();\n`);
await cp(path.join(here, 'manifest.json'), path.join(dist, 'manifest.json'));
await mkdir(path.join(dist, 'icons'));
for (const size of [32, 128]) await cp(path.join(root, `assets/icons/${size}x${size}.png`), path.join(dist, `icons/${size}.png`));
