// Known vulnerabilities in the components of an SBOM (CRA Annex I, Part II, points 1 and 2),
// with a flag for vulnerabilities known to be exploited in the wild, which is where the
// Article 14 reporting clock (24 h early warning) can start.
//
// Sources: OSV.dev (vulnerabilities per package), CISA KEV and ENISA EUVD (exploitation).
// CocoaPods has no vulnerability database of its own: a pod is checked as the npm package it comes from (Capacitor,
// React Native) or as its git repository in the Swift ecosystem (GitHub Advisory Database), found in its podspec.

import { createHash } from 'node:crypto';
import { cvss3Score, labelForScore } from './cvss.mjs';
import { swiftPurl } from './mobile.mjs';

const OSV = 'https://api.osv.dev/v1';
const KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EUVD = 'https://euvdservices.enisa.europa.eu/api/search';
const PODSPECS = 'https://cdn.cocoapods.org/Specs';

// purl types with an OSV.dev ecosystem (https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt)
const OSV_TYPES = new Set(['npm', 'composer', 'maven', 'swift', 'pypi', 'gem', 'golang', 'cargo', 'nuget', 'pub', 'hex', 'hackage', 'cran', 'deb', 'apk', 'rpm']);

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

async function getJson(url, init, tries = 3) {
    for (let attempt = 1; ; attempt++) {
        try {
            const res = await fetch(url, { ...init, headers: { 'user-agent': 'vulnclock', ...(init?.headers || {}) } });
            if (!res.ok) throw Object.assign(new Error(`${res.status} ${res.statusText} from ${url}`), { status: res.status });
            return await res.json();
        } catch (err) {
            const final = err.status >= 400 && err.status < 500 && err.status !== 429;
            if (final || attempt >= tries) throw err;
            await new Promise((r) => setTimeout(r, 1000 * attempt));
        }
    }
}

async function mapLimit(items, limit, fn) {
    const out = new Array(items.length);
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
        while (next < items.length) {
            const i = next++;
            out[i] = await fn(items[i], i);
        }
    }));
    return out;
}

const basePurl = (purl) => purl.split(/[?#]/)[0];
const typeOf = (purl) => (String(purl).match(/^pkg:([^/]+)\//) || [])[1]?.toLowerCase() || '';
const propOf = (c, name) => (c.properties || []).find((p) => p.name === name)?.value;
const labelOf = (c) => (c.group ? `${c.group}/${c.name}` : c.name);
const npmName = (purl) => decodeURIComponent(basePurl(purl).replace(/^pkg:npm\//, '').replace(/@[^/@]+$/, ''));

// The git repository of a pod version, from its podspec on the CocoaPods CDN (Specs/<md5 of the name, 3 levels>/...).
export async function podGitSource(pod, version, fetchJson = getJson) {
    const h = createHash('md5').update(pod).digest('hex');
    const spec = await fetchJson(`${PODSPECS}/${h[0]}/${h[1]}/${h[2]}/${pod}/${version}/${pod}.podspec.json`);
    return spec?.source?.git || null;
}

function severityOf(vuln) {
    const label = String(vuln.database_specific?.severity || '').toUpperCase();
    const vectors = (vuln.severity || []).map((s) => s.score).filter(Boolean);
    const v3 = vectors.find((v) => v.startsWith('CVSS:3'));
    const score = v3 ? cvss3Score(v3) : null;
    const fromLabel = { MODERATE: 'MEDIUM' }[label] || (SEVERITIES.includes(label) ? label : null);
    return { severity: fromLabel || labelForScore(score), score, vector: v3 || vectors[0] || null };
}

function fixedVersions(vuln, component) {
    const fixed = new Set();
    for (const a of vuln.affected || []) {
        const p = a.package || {};
        const samePurl = p.purl && basePurl(p.purl).split('@')[0] === basePurl(component.purl).split('@')[0];
        const sameName = p.name && [component.name, component.group ? `${component.group}/${component.name}` : null].includes(p.name);
        if (!samePurl && !sameName) continue;
        for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) fixed.add(e.fixed);
    }
    return [...fixed];
}

export async function scan(bom, { kev = true, euvd = true, log = () => {}, fetchJson = getJson, podSource = (pod, version) => podGitSource(pod, version, fetchJson) } = {}) {
    const all = (bom.components || []).filter((c) => c.purl);
    const versioned = (c) => /@[^/]+$/.test(basePurl(c.purl));
    const npmInBom = new Set(all.filter((c) => typeOf(c.purl) === 'npm').map((c) => npmName(c.purl)));

    // What each component is checked as. A purl without a version would match every advisory the package ever had,
    // and a purl type OSV.dev has no database for matches nothing: both are listed in the report, not counted as checked.
    const targets = [];
    const unversioned = [];
    const uncovered = [];
    const pods = [];
    let viaNpm = 0;
    for (const c of all) {
        const t = typeOf(c.purl);
        if (!versioned(c)) unversioned.push(labelOf(c));
        else if (t === 'cocoapods') pods.push(c);
        else if (OSV_TYPES.has(t)) targets.push({ c, purl: basePurl(c.purl) });
        else uncovered.push(labelOf(c));
    }
    if (pods.length) log(`Finding the sources of ${pods.length} CocoaPods pods`);
    await mapLimit(pods, 8, async (c) => {
        const npm = propOf(c, 'vulnclock:npm-package');
        if (npm && npmInBom.has(npm)) { viaNpm++; return; } // the same code, already checked as the npm package
        if (npm) { targets.push({ c, purl: `pkg:npm/${npm.replace(/^@/, '%40')}@${c.version}`, via: `npm ${npm}` }); return; }
        const git = propOf(c, 'vulnclock:git') || (await podSource(c.name, c.version).catch(() => null));
        const id = git && swiftPurl(git, c.version);
        if (id) targets.push({ c, purl: id.purl, via: `${id.group}/${id.name}` });
        else uncovered.push(labelOf(c));
    });
    const checked = targets.length + viaNpm;
    log(`Checking ${checked} components against OSV.dev${unversioned.length + uncovered.length ? ` (${unversioned.length + uncovered.length} cannot be checked)` : ''}`);

    const hits = new Map(); // vuln id -> target indexes
    for (let i = 0; i < targets.length; i += 1000) {
        const batch = targets.slice(i, i + 1000);
        const res = await fetchJson(`${OSV}/querybatch`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ queries: batch.map((t) => ({ package: { purl: t.purl } })) }),
        });
        res.results.forEach((r, j) => {
            for (const v of r.vulns || []) {
                if (!hits.has(v.id)) hits.set(v.id, new Set());
                hits.get(v.id).add(i + j);
            }
        });
    }

    const ids = [...hits.keys()];
    log(`${ids.length} advisories match; fetching details`);
    const details = await mapLimit(ids, 8, (id) => fetchJson(`${OSV}/vulns/${encodeURIComponent(id)}`));

    // One finding per component and vulnerability; aliases (GHSA, CVE, ...) of the same issue are merged.
    const findings = [];
    const seen = new Map();
    details.forEach((v) => {
        if (!v || v.withdrawn) return;
        const names = [v.id, ...(v.aliases || [])];
        for (const ti of hits.get(v.id)) {
            const { c, purl, via } = targets[ti];
            const key = names.map((n) => `${c['bom-ref'] || c.purl}|${n}`).find((k) => seen.has(k));
            if (key) {
                const f = seen.get(key);
                f.aliases = [...new Set([...f.aliases, ...names.filter((n) => n !== f.id)])];
                continue;
            }
            const sev = severityOf(v);
            const f = {
                id: v.id,
                aliases: (v.aliases || []).slice(),
                summary: v.summary || (v.details || '').split('\n')[0].slice(0, 200),
                ...sev,
                component: labelOf(c),
                version: c.version,
                purl: c.purl,
                ...(via ? { checkedAs: via } : {}),
                shippedDev: (c.properties || []).some((p) => p.name === 'vulnclock:shipped-dev-dependency'),
                fixed: fixedVersions(v, { ...c, purl }),
                published: v.published || null,
                url: `https://osv.dev/vulnerability/${v.id}`,
                exploited: null,
                euvd: null,
            };
            findings.push(f);
            for (const n of names) seen.set(`${c['bom-ref'] || c.purl}|${n}`, f);
        }
    });

    const cves = (f) => [f.id, ...f.aliases].filter((n) => /^CVE-\d{4}-\d+$/.test(n));

    if (kev && findings.length) {
        log('Checking CISA Known Exploited Vulnerabilities');
        try {
            const cat = await fetchJson(KEV);
            const byCve = new Map((cat.vulnerabilities || []).map((x) => [x.cveID, x]));
            for (const f of findings) {
                const hit = cves(f).map((c) => byCve.get(c)).find(Boolean);
                if (hit) f.exploited = { source: 'CISA KEV', since: hit.dateAdded, ransomware: hit.knownRansomwareCampaignUse === 'Known' };
            }
        } catch (err) {
            log(`CISA KEV not reachable (${err.message}); exploitation not checked there`);
        }
    }

    if (euvd && findings.length) {
        log('Checking ENISA EU Vulnerability Database');
        await mapLimit(findings, 4, async (f) => {
            const keys = [...cves(f), f.id, ...f.aliases.filter((a) => a.startsWith('GHSA-'))];
            for (const k of [...new Set(keys)]) {
                try {
                    const res = await fetchJson(`${EUVD}?text=${encodeURIComponent(k)}&size=5&page=0`);
                    const item = (res.items || []).find((it) => String(it.aliases || '').split(/\s+/).includes(k) || it.id === k);
                    if (!item) continue;
                    f.euvd = item.id;
                    if (item.exploitedSince && !f.exploited) f.exploited = { source: 'ENISA EUVD', since: item.exploitedSince };
                    return;
                } catch {
                    return;
                }
            }
        });
    }

    findings.sort((a, b) => (b.exploited ? 1 : 0) - (a.exploited ? 1 : 0) || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || (b.score || 0) - (a.score || 0) || a.component.localeCompare(b.component));
    const counts = Object.fromEntries(SEVERITIES.map((s) => [s.toLowerCase(), findings.filter((f) => f.severity === s).length]));
    counts.exploited = findings.filter((f) => f.exploited).length;
    counts.total = findings.length;

    const meta = bom.metadata?.component || {};
    return {
        generatedAt: new Date().toISOString(),
        product: { name: meta.name || null, version: meta.version || null },
        components: checked,
        unversioned,
        uncovered,
        sources: ['OSV.dev', kev && 'CISA KEV', euvd && 'ENISA EUVD'].filter(Boolean),
        counts,
        findings,
    };
}

export function failsThreshold(result, failOn) {
    if (!failOn || failOn === 'none') return false;
    if (failOn === 'exploited') return result.counts.exploited > 0;
    const limit = SEVERITIES.indexOf(failOn.toUpperCase());
    if (limit < 0) throw new Error(`--fail-on must be none, exploited, critical, high, medium or low (got ${failOn})`);
    return result.findings.some((f) => f.exploited || (SEVERITIES.indexOf(f.severity) <= limit && f.severity !== 'UNKNOWN'));
}
