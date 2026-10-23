#!/usr/bin/env node
// VulnClock: SBOM, vulnerability check and monitoring for the EU Cyber Resilience Act.
//
//   vulnclock sbom  [dir] --out sbom.cdx.json [--ecosystem npm,composer,gradle,cocoapods,spm] [--ship-dev electron] [--include-dev] [--name N] [--version V] [--manufacturer M]
//   vulnclock scan  --sbom sbom.cdx.json [--out findings.json] [--md report.md] [--fail-on none|exploited|critical|high|medium|low]
//   vulnclock check [dir] [sbom options] [scan options]        (sbom + scan in one go)
//   vulnclock issue --findings findings.json [--repo owner/name] [--label cra]   (GitHub issue for monitoring, needs gh)
//   vulnclock upload --findings findings.json --sbom sbom.cdx.json [--version V] [--ref R] [--commit C] [--run-url U]   (to VulnClock Pro, token in VULNCLOCK_TOKEN)

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateSbom } from '../lib/sbom.mjs';
import { scan, failsThreshold } from '../lib/scan.mjs';
import { toMarkdown, issueBody, idsFromBody } from '../lib/report.mjs';
import { upload, DEFAULT_URL } from '../lib/upload.mjs';

const FLAGS = new Set(['include-dev', 'no-kev', 'no-euvd', 'quiet']);

function parse(argv) {
    const args = { _: [] };
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (!a.startsWith('--')) { args._.push(a); continue; }
        const key = a.slice(2);
        if (FLAGS.has(key)) args[key] = true;
        else args[key] = argv[++i];
    }
    return args;
}

const list = (v) => (v ? String(v).split(',').map((s) => s.trim()).filter(Boolean) : []);
const writeJson = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n');

function sbomCommand(args) {
    const dir = args._[1] || '.';
    const bom = generateSbom(dir, {
        ecosystem: args.ecosystem,
        warn: (m) => process.stderr.write(`vulnclock: ${m}\n`),
        shipDev: list(args['ship-dev']),
        includeDev: !!args['include-dev'],
        name: args.name,
        version: args.version,
        manufacturer: args.manufacturer,
    });
    const out = args.out || args.sbom || 'sbom.cdx.json';
    writeJson(out, bom);
    if (!bom.components.length && !args['include-dev']) {
        process.stderr.write('vulnclock: no production dependencies. If your build bundles devDependencies into what you ship (Vite, webpack, Electron), use --include-dev or --ship-dev.\n');
    }
    return { bom, out };
}

async function scanCommand(args, bom) {
    bom = bom || JSON.parse(fs.readFileSync(args.sbom || 'sbom.cdx.json', 'utf8'));
    const log = args.quiet ? () => {} : (m) => process.stderr.write(`${m}\n`);
    const result = await scan(bom, { kev: !args['no-kev'], euvd: !args['no-euvd'], log });
    writeJson(args.out && args._[0] === 'scan' ? args.out : args.findings || 'cra-findings.json', result);
    const md = toMarkdown(result, { wizardUrl: args['wizard-url'] });
    if (args.md) fs.writeFileSync(args.md, md);
    if (!args.quiet) process.stdout.write(md);
    if (process.env.GITHUB_OUTPUT) {
        fs.appendFileSync(process.env.GITHUB_OUTPUT, `findings=${result.counts.total}\nexploited=${result.counts.exploited}\ncritical=${result.counts.critical}\nhigh=${result.counts.high}\n`);
    }
    return failsThreshold(result, args['fail-on']) ? 1 : 0;
}

function gh(args, input) {
    return execFileSync('gh', args, { encoding: 'utf8', input, stdio: [input ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
}

function issueCommand(args) {
    const result = JSON.parse(fs.readFileSync(args.findings || 'cra-findings.json', 'utf8'));
    const repo = args.repo || process.env.GITHUB_REPOSITORY;
    if (!repo) throw new Error('--repo owner/name is required outside GitHub Actions');
    const label = args.label || 'cra';
    const product = [result.product.name, result.product.version].filter(Boolean).join(' ') || repo;
    const title = `CRA: known vulnerabilities in ${result.product.name || repo}`;

    const open = JSON.parse(gh(['issue', 'list', '--repo', repo, '--label', label, '--state', 'open', '--json', 'number,body', '--limit', '1']) || '[]');
    const existing = open[0];
    const tmp = path.join(os.tmpdir(), `vulnclock-${process.pid}.md`);

    if (!result.counts.total) {
        if (existing) {
            gh(['issue', 'comment', String(existing.number), '--repo', repo, '--body', `No known vulnerabilities in ${product} any more (checked ${result.generatedAt}). Closing.`]);
            gh(['issue', 'close', String(existing.number), '--repo', repo]);
        }
        console.log('No findings.');
        return 0;
    }

    const body = issueBody(result, { wizardUrl: args['wizard-url'] });
    fs.writeFileSync(tmp, body);
    gh(['label', 'create', label, '--repo', repo, '--color', 'B60205', '--description', 'EU Cyber Resilience Act: vulnerability handling', '--force']);

    if (!existing) {
        const url = gh(['issue', 'create', '--repo', repo, '--title', title, '--label', label, '--body-file', tmp]).trim();
        console.log(`Opened ${url}`);
    } else {
        const before = idsFromBody(existing.body);
        const now = idsFromBody(body);
        const added = [...now].filter((id) => !before.has(id));
        gh(['issue', 'edit', String(existing.number), '--repo', repo, '--body-file', tmp]);
        const newlyExploited = added.filter((id) => id.endsWith('!'));
        if (newlyExploited.length) {
            gh(['label', 'create', `${label}-24h`, '--repo', repo, '--color', 'D93F0B', '--description', 'Exploited in the wild: check the CRA 24 h early warning today', '--force']);
            gh(['issue', 'edit', String(existing.number), '--repo', repo, '--add-label', `${label}-24h`]);
        }
        if (added.length) {
            const lines = added.map((id) => `- ${id.replace(/!$/, ' (exploited in the wild)')}`).join('\n');
            gh(['issue', 'comment', String(existing.number), '--repo', repo, '--body', `New since the last check:\n\n${lines}\n\n${newlyExploited.length ? 'Exploited in the wild: decide today whether the CRA Article 14 early warning (24 h) applies, and write down when you became aware.' : ''}`]);
        }
        console.log(`Updated issue #${existing.number} (${added.length} new)`);
    }
    fs.rmSync(tmp, { force: true });
    return 0;
}

async function uploadCommand(args) {
    const result = JSON.parse(fs.readFileSync(args.findings || 'cra-findings.json', 'utf8'));
    const sbomFile = args.sbom || 'sbom.cdx.json';
    const sbom = fs.existsSync(sbomFile) ? JSON.parse(fs.readFileSync(sbomFile, 'utf8')) : undefined;
    const data = await upload({
        url: args.url || process.env.VULNCLOCK_URL || DEFAULT_URL,
        token: process.env.VULNCLOCK_TOKEN,
        result,
        sbom,
        meta: { version: args.version, ref: args.ref, commit: args.commit, runUrl: args['run-url'] },
    });
    console.log(`Uploaded to VulnClock: ${data.new ?? 0} new, ${data.exploited ?? 0} newly exploited, ${data.gone ?? 0} no longer reported.${data.dashboard ? ` ${data.dashboard}` : ''}`);
    return 0;
}

async function main() {
    const args = parse(process.argv.slice(2));
    const cmd = args._[0];
    if (cmd === 'sbom') {
        const { bom, out } = sbomCommand(args);
        console.log(`SBOM with ${bom.components.length} components written to ${out}`);
        return 0;
    }
    if (cmd === 'scan') return scanCommand(args);
    if (cmd === 'check') {
        const { bom, out } = sbomCommand(args);
        if (!args.quiet) process.stderr.write(`SBOM with ${bom.components.length} components written to ${out}\n`);
        return scanCommand(args, bom);
    }
    if (cmd === 'issue') return issueCommand(args);
    if (cmd === 'upload') return uploadCommand(args);
    console.log(fs.readFileSync(new URL(import.meta.url), 'utf8').split('\n').slice(1, 9).join('\n').replace(/^\/\/ ?/gm, ''));
    return cmd ? 2 : 0;
}

// exitCode instead of process.exit(): exiting while an HTTPS connection is still closing crashes Node on Windows
// (libuv assertion in src\win\async.c), so let the process end on its own.
main().then((code) => { process.exitCode = code; }, (err) => {
    console.error(`vulnclock: ${err.message}`);
    process.exitCode = 2;
});
