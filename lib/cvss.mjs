// CVSS v3.0 / v3.1 base score from a vector string (FIRST CVSS v3.1 specification, section 7).
// CVSS v4 vectors are not scored here; callers fall back to the advisory's own severity label.

const W = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    UI: { N: 0.85, R: 0.62 },
    CIA: { H: 0.56, L: 0.22, N: 0 },
};

// Round up to one decimal the way the specification defines it (avoids floating point artefacts).
function roundUp(x) {
    const i = Math.round(x * 100000);
    return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export function cvss3Score(vector) {
    if (typeof vector !== 'string' || !/^CVSS:3\.[01]\//.test(vector)) return null;
    const m = Object.fromEntries(vector.split('/').slice(1).map((p) => p.split(':')));
    const changed = m.S === 'C';
    const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
    const av = W.AV[m.AV], ac = W.AC[m.AC], ui = W.UI[m.UI];
    const c = W.CIA[m.C], i = W.CIA[m.I], a = W.CIA[m.A];
    if ([pr, av, ac, ui, c, i, a].some((v) => v === undefined)) return null;
    const iss = 1 - (1 - c) * (1 - i) * (1 - a);
    const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
    const exploitability = 8.22 * av * ac * pr * ui;
    if (impact <= 0) return 0;
    return changed ? roundUp(Math.min(1.08 * (impact + exploitability), 10)) : roundUp(Math.min(impact + exploitability, 10));
}

export function labelForScore(score) {
    if (score === null || score === undefined) return 'UNKNOWN';
    if (score === 0) return 'NONE';
    if (score < 4) return 'LOW';
    if (score < 7) return 'MEDIUM';
    if (score < 9) return 'HIGH';
    return 'CRITICAL';
}
