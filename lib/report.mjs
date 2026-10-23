// Human-readable reports of a scan result: the job summary / file report and the monitoring issue body.

const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

export const MARKER = '<!-- vulnclock:ids';

function table(findings) {
    const rows = findings.map((f) => {
        const ids = [f.id, ...f.aliases.filter((a) => a.startsWith('CVE-'))].slice(0, 3).join(', ');
        const exploited = f.exploited ? `**yes** (${f.exploited.source}, ${f.exploited.since})` : 'no';
        const comp = `${f.component}${f.shippedDev ? ' (shipped dev dependency)' : ''}${f.checkedAs ? ` (checked as ${f.checkedAs})` : ''}`;
        return `| ${f.severity}${f.score ? ` ${f.score}` : ''} | ${esc(comp)} | ${esc(f.version)} | [${esc(ids)}](${f.url}) ${esc(f.summary)} | ${esc(f.fixed.join(', ') || 'no fix listed')} | ${exploited} |`;
    });
    return ['| Severity | Component | Version | Vulnerability | Fixed in | Exploited in the wild |', '| --- | --- | --- | --- | --- | --- |', ...rows].join('\n');
}

export function toMarkdown(result, { wizardUrl } = {}) {
    const { product, counts } = result;
    const name = [product.name, product.version].filter(Boolean).join(' ') || 'product';
    const lines = [`# CRA vulnerability check: ${name}`, ''];
    lines.push(`Checked ${result.components} components on ${result.generatedAt.slice(0, 16).replace('T', ' ')} UTC against ${result.sources.join(', ')}.`, '');
    if (result.unversioned?.length) {
        lines.push(`**Not checked (version unknown):** ${result.unversioned.map(esc).join(', ')}. Pin their versions or commit the lock file (Podfile.lock, Package.resolved, gradle.lockfile) so they can be checked.`, '');
    }
    if (result.uncovered?.length) {
        lines.push(`**Not checked (no vulnerability database covers them):** ${result.uncovered.map(esc).join(', ')}. Watch their own security announcements.`, '');
    }

    if (!counts.total) {
        const unchecked = (result.unversioned?.length || 0) + (result.uncovered?.length || 0);
        lines.push(unchecked ? `**No known vulnerabilities in the ${result.components} checked components** (${unchecked} could not be checked, see above).` : '**No known vulnerabilities in the components of this SBOM.**');
        return lines.join('\n') + '\n';
    }
    const parts = ['critical', 'high', 'medium', 'low', 'unknown'].filter((k) => counts[k]).map((k) => `${counts[k]} ${k}`);
    lines.push(`**${counts.total} known vulnerabilities** (${parts.join(', ')}). ${counts.exploited ? `**${counts.exploited} known to be exploited in the wild.**` : 'None is listed as exploited in the wild.'}`, '');

    if (counts.exploited) {
        lines.push(
            '> **Check the exploited ones today.** Under Article 14 of the Cyber Resilience Act, an actively exploited vulnerability in your product must get an early warning to the CSIRT and ENISA within 24 hours of you becoming aware of it, a notification within 72 hours and a final report within 14 days after a fix is available. A vulnerability exploited somewhere else is not automatically exploited in your product: check whether your product uses the affected code, and record what you decided and when.',
            ...(wizardUrl ? [`> Reporting helper: ${wizardUrl}`] : []),
            '',
        );
    }
    lines.push(table(result.findings), '');
    lines.push('Under Annex I, Part II of the Cyber Resilience Act these have to be addressed without delay, by security updates where possible, and fixed vulnerabilities disclosed once an update is out.');
    return lines.join('\n') + '\n';
}

// The issue body carries the ids it lists, so the next run can tell what is new.
export function issueBody(result, opts = {}) {
    const ids = result.findings.map((f) => `${f.id}@${f.component}@${f.version}${f.exploited ? '!' : ''}`);
    return `${toMarkdown(result, opts)}\n${MARKER} ${ids.join(' ')} -->\n`;
}

export function idsFromBody(body) {
    const m = String(body || '').match(/<!-- vulnclock:ids ([^>]*?) ?-->/);
    return new Set(m ? m[1].split(/\s+/).filter(Boolean) : []);
}
