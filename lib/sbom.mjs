// Software bill of materials (CRA Annex I, Part II, point 1) in CycloneDX 1.5 JSON.
// npm: `npm sbom` from package-lock.json. Composer: composer.lock. Android: Gradle build files (lib/mobile.mjs).
// iOS: Podfile.lock / Package.resolved / Package.swift. A Capacitor or React Native app has several of these; they are merged.
// Anything else: use Syft and pass its file to `scan`.

import { execSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { androidRoot, iosRoots, gradleComponents, cocoapodsComponents, spmComponents } from './mobile.mjs';

export const TOOL = { name: 'VulnClock', version: '0.2.1' };
export const ECOSYSTEMS = ['npm', 'composer', 'gradle', 'cocoapods', 'spm'];

export function detectEcosystems(dir) {
    const has = (f) => fs.existsSync(path.join(dir, f));
    const ios = iosRoots(dir);
    return [
        has('package-lock.json') && 'npm',
        has('composer.lock') && 'composer',
        androidRoot(dir) && 'gradle',
        ios.some((d) => fs.existsSync(path.join(d, 'Podfile.lock')) || fs.existsSync(path.join(d, 'Podfile'))) && 'cocoapods',
        ios.some((d) => fs.existsSync(path.join(d, 'Package.resolved')) || fs.readdirSync(d).some((n) => n.endsWith('.xcworkspace') || n.endsWith('.xcodeproj'))) && 'spm',
    ].filter(Boolean);
}

export function detectEcosystem(dir) {
    return detectEcosystems(dir)[0] || null;
}

function readJson(file) {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
}

// `npm sbom` refuses a root package.json without a version (common in apps that are never published),
// so such projects are read from a temporary copy of package.json + package-lock.json with a version added.
function npmSbomJson(dir, omitDev) {
    const cmd = `npm sbom --sbom-format cyclonedx --package-lock-only${omitDev ? ' --omit dev' : ''}`;
    const pkg = readJson(path.join(dir, 'package.json'));
    let cwd = dir, tmp = null;
    if (!pkg.version && !pkg.workspaces) {
        tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnclock-'));
        fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({ ...pkg, name: pkg.name || path.basename(path.resolve(dir)), version: '0.0.0' }));
        fs.copyFileSync(path.join(dir, 'package-lock.json'), path.join(tmp, 'package-lock.json'));
        cwd = tmp;
    }
    try {
        const bom = JSON.parse(execSync(cmd, { cwd, encoding: 'utf8', maxBuffer: 512 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] }));
        if (tmp && bom.metadata?.component) delete bom.metadata.component.version; // the 0.0.0 was only for npm
        return bom;
    } finally {
        if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
    }
}

// Production dependencies plus the dev dependencies that ship inside the product
// (for an Electron app the Electron runtime is a devDependency but is in every installer).
function npmBom(dir, { shipDev = [], includeDev = false }) {
    if (includeDev) return npmSbomJson(dir, false);
    const prod = npmSbomJson(dir, true);
    if (!shipDev.length) return prod;

    const full = npmSbomJson(dir, false);
    const graph = new Map((full.dependencies || []).map((d) => [d.ref, d.dependsOn || []]));
    const rootRef = full.metadata?.component?.['bom-ref'];
    const direct = graph.get(rootRef) || [];
    const start = direct.filter((ref) => shipDev.some((name) => ref.startsWith(`${name}@`)));
    const missing = shipDev.filter((name) => !start.some((ref) => ref.startsWith(`${name}@`)));
    if (missing.length) throw new Error(`--ship-dev: not a direct dependency of the project: ${missing.join(', ')}`);

    const keep = new Set((prod.components || []).map((c) => c['bom-ref']));
    const shipped = new Set();
    const stack = [...start];
    while (stack.length) {
        const ref = stack.pop();
        if (shipped.has(ref)) continue;
        shipped.add(ref);
        for (const next of graph.get(ref) || []) stack.push(next);
    }
    const byRef = new Map((full.components || []).map((c) => [c['bom-ref'], c]));
    const components = [...(prod.components || [])];
    for (const ref of shipped) {
        if (keep.has(ref) || !byRef.has(ref)) continue;
        const c = structuredClone(byRef.get(ref));
        c.properties = [...(c.properties || []).filter((p) => p.name !== 'cdx:npm:package:development'), { name: 'vulnclock:shipped-dev-dependency', value: 'true' }];
        components.push(c);
        keep.add(ref);
    }
    const dependencies = (full.dependencies || [])
        .filter((d) => d.ref === rootRef || keep.has(d.ref))
        .map((d) => ({ ref: d.ref, dependsOn: (d.dependsOn || []).filter((r) => keep.has(r)) }));
    return { ...prod, components, dependencies };
}

function composerBom(dir, { includeDev = false }) {
    const lock = readJson(path.join(dir, 'composer.lock'));
    const manifest = fs.existsSync(path.join(dir, 'composer.json')) ? readJson(path.join(dir, 'composer.json')) : {};
    const packages = [...(lock.packages || []), ...(includeDev ? lock['packages-dev'] || [] : [])];
    const purl = (p) => `pkg:composer/${p.name}@${p.version}`;
    const names = new Map(packages.map((p) => [p.name.toLowerCase(), purl(p)]));
    const components = packages.map((p) => {
        const [group, name] = p.name.split('/');
        return {
            type: 'library',
            'bom-ref': purl(p),
            group,
            name,
            version: p.version,
            purl: purl(p),
            ...(p.license?.length ? { licenses: p.license.map((id) => ({ license: { id } })) } : {}),
        };
    });
    const dependsOn = (req) => Object.keys(req || {}).map((n) => names.get(n.toLowerCase())).filter(Boolean);
    const rootRef = `${manifest.name || path.basename(path.resolve(dir))}@${manifest.version || '0.0.0'}`;
    const dependencies = [
        { ref: rootRef, dependsOn: dependsOn({ ...manifest.require, ...(includeDev ? manifest['require-dev'] : {}) }) },
        ...packages.map((p) => ({ ref: purl(p), dependsOn: dependsOn(p.require) })),
    ];
    return {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        metadata: { component: { type: 'application', 'bom-ref': rootRef, name: manifest.name || path.basename(path.resolve(dir)), ...(manifest.version ? { version: manifest.version } : {}) } },
        components,
        dependencies,
    };
}

function emptyBom(dir) {
    const name = path.basename(path.resolve(dir));
    return { bomFormat: 'CycloneDX', specVersion: '1.5', metadata: { component: { type: 'application', 'bom-ref': name, name } }, components: [], dependencies: [] };
}

export function generateSbom(dir, opts = {}) {
    const ecos = opts.ecosystem ? String(opts.ecosystem).split(',').map((s) => s.trim()).filter(Boolean) : detectEcosystems(dir);
    const unknown = ecos.filter((e) => !ECOSYSTEMS.includes(e));
    if (unknown.length) throw new Error(`Unknown ecosystem: ${unknown.join(', ')} (use ${ECOSYSTEMS.join(', ')})`);
    if (!ecos.length) throw new Error(`No package-lock.json, composer.lock, Gradle or iOS project in ${dir}. Generate the SBOM with Syft and pass it to \`vulnclock scan --sbom\`.`);
    const warn = opts.warn || (() => {});

    const bom = ecos.includes('npm') ? npmBom(dir, opts) : ecos.includes('composer') ? composerBom(dir, opts) : emptyBom(dir);
    const rootRef = bom.metadata?.component?.['bom-ref'];
    const add = (components) => {
        const known = new Set((bom.components || []).map((c) => c['bom-ref']));
        const fresh = components.filter((c) => !known.has(c['bom-ref']));
        bom.components = [...(bom.components || []), ...fresh];
        bom.dependencies = bom.dependencies || [];
        const root = bom.dependencies.find((d) => d.ref === rootRef) || (bom.dependencies.push({ ref: rootRef, dependsOn: [] }), bom.dependencies.at(-1));
        root.dependsOn = [...new Set([...(root.dependsOn || []), ...fresh.map((c) => c['bom-ref'])])];
    };
    if (ecos.includes('npm') && ecos.includes('composer')) add(composerBom(dir, opts).components);
    if (ecos.includes('gradle')) add(gradleComponents(dir, warn));
    if (ecos.includes('cocoapods')) add(cocoapodsComponents(dir, warn));
    if (ecos.includes('spm')) add(spmComponents(dir, warn));
    const eco = ecos.join(',');

    const component = { ...(bom.metadata?.component || {}), type: 'application' };
    // npm sbom names the product after its folder; package.json has the real name
    const pkgName = ecos.includes('npm') && fs.existsSync(path.join(dir, 'package.json')) ? readJson(path.join(dir, 'package.json')).name : null;
    if (opts.name) component.name = opts.name;
    else if (pkgName) component.name = pkgName;
    if (opts.version) component.version = opts.version;
    bom.serialNumber = `urn:uuid:${randomUUID()}`;
    bom.version = 1;
    bom.metadata = {
        ...(bom.metadata || {}),
        timestamp: new Date().toISOString(),
        tools: { components: [{ type: 'application', name: TOOL.name, version: TOOL.version }] },
        component,
        // CycloneDX 1.5 has no metadata.manufacturer (added in 1.6); supplier is the 1.5 field for the maker of the product.
        ...(opts.manufacturer ? { supplier: { name: opts.manufacturer } } : {}),
        properties: [
            ...(bom.metadata?.properties || []),
            { name: 'vulnclock:ecosystems', value: eco },
            { name: 'vulnclock:scope', value: opts.includeDev ? 'all dependencies' : opts.shipDev?.length ? `production + shipped dev: ${opts.shipDev.join(', ')}` : 'production dependencies' },
            ...(ecos.includes('gradle') ? [{ name: 'vulnclock:gradle', value: 'declared dependencies of every module (top level), or gradle.lockfile when present' }] : []),
        ],
    };
    return bom;
}
