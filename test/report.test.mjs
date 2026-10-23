import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cvss3Score, labelForScore } from '../lib/cvss.mjs';
import { issueBody, idsFromBody } from '../lib/report.mjs';
import { failsThreshold } from '../lib/scan.mjs';

test('CVSS 3.1 base scores match the FIRST calculator', () => {
    assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
    assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H'), 9);
    assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
    assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N'), 5.4);
    assert.equal(cvss3Score('CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'), 5.5);
    assert.equal(cvss3Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'), null);
    assert.equal(labelForScore(7.5), 'HIGH');
    assert.equal(labelForScore(null), 'UNKNOWN');
});

const result = {
    generatedAt: '2026-10-22T10:00:00.000Z',
    product: { name: 'demo', version: '1.0.0' },
    components: 2,
    sources: ['OSV.dev'],
    counts: { total: 2, critical: 1, high: 0, medium: 1, low: 0, unknown: 0, exploited: 1 },
    findings: [
        { id: 'GHSA-1', aliases: ['CVE-2021-1'], summary: 's', severity: 'CRITICAL', score: 10, component: 'a', version: '1', fixed: ['2'], url: 'u', exploited: { source: 'CISA KEV', since: '2021-12-10' } },
        { id: 'GHSA-2', aliases: [], summary: 't', severity: 'MEDIUM', score: 5, component: 'b', version: '1', fixed: [], url: 'u', exploited: null },
    ],
};

test('the issue body round-trips the ids it lists, with the exploited mark', () => {
    assert.deepEqual([...idsFromBody(issueBody(result))], ['GHSA-1@a@1!', 'GHSA-2@b@1']);
    assert.equal(idsFromBody('no marker').size, 0);
});

test('fail-on thresholds', () => {
    assert.equal(failsThreshold(result, 'none'), false);
    assert.equal(failsThreshold(result, 'exploited'), true);
    assert.equal(failsThreshold(result, 'critical'), true);
    assert.equal(failsThreshold({ ...result, counts: { ...result.counts, exploited: 0 }, findings: [result.findings[1]] }, 'high'), false);
    assert.throws(() => failsThreshold(result, 'bogus'));
});
