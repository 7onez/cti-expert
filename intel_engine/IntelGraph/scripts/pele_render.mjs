// pele_render.mjs — render one Mermaid file to SVG with Pele. Driven by render_mermaid.py.
//
//   node pele_render.mjs <pele.mjs> <diagram.mmd> '<render options JSON>'    (or: bun …)
//
// Prints {"svg", "width", "height", "type"} as JSON on stdout. A diagram Pele cannot parse exits 2
// with the parser's message on stderr (it quotes the offending source line); anything else exits 1.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const [peleModule, mmdPath, optionsJson = '{}'] = process.argv.slice(2);
if (!peleModule || !mmdPath) {
  process.stderr.write('usage: pele_render.mjs <pele.mjs> <diagram.mmd> [options JSON]\n');
  process.exit(1);
}
const { render, PeleError } = await import(pathToFileURL(peleModule).href);
try {
  const r = render(readFileSync(mmdPath, 'utf8'), JSON.parse(optionsJson));
  process.stdout.write(JSON.stringify({ svg: r.svg, width: r.width, height: r.height, type: r.type }));
} catch (error) {
  process.stderr.write(`${error && error.message ? error.message : error}\n`);
  process.exit(error instanceof PeleError ? 2 : 1);
}
