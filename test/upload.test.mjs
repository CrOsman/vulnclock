import { test } from 'node:test';
import assert from 'node:assert/strict';
import { upload } from '../lib/upload.mjs';

const result = { product: { name: 'App', version: '1.2.0' }, findings: [], counts: { total: 0 } };

test('upload sends the check with the token only in the Authorization header', async () => {
    let seen;
    const fetchImpl = async (url, init) => {
        seen = { url, init };
        return { ok: true, status: 201, text: async () => JSON.stringify({ new: 1, exploited: 0, gone: 0, dashboard: 'https://app.vulnclock.com/products/1' }) };
    };
    const data = await upload({ url: 'https://app.vulnclock.com/api/v1/scans', token: 'vc_secret', result, sbom: { bomFormat: 'CycloneDX' }, meta: { ref: 'v1.2.0', commit: 'abc', runUrl: '' }, fetchImpl });
    assert.equal(data.new, 1);
    assert.equal(seen.init.headers.authorization, 'Bearer vc_secret');
    const body = JSON.parse(seen.init.body);
    assert.equal(body.version, '1.2.0');
    assert.equal(body.ref, 'v1.2.0');
    assert.equal('run_url' in body, false);
    assert.equal(body.sbom.bomFormat, 'CycloneDX');
    assert.equal(JSON.stringify(body).includes('vc_secret'), false);
});

test('upload refuses without a token, over plain http, and reports the server message', async () => {
    await assert.rejects(upload({ token: '', result }), /no VulnClock token/);
    await assert.rejects(upload({ url: 'http://example.com/api', token: 'vc_x', result }), /https/);
    const refused = async () => ({ ok: false, status: 402, text: async () => JSON.stringify({ message: 'The VulnClock subscription of this account is not active.' }) });
    await assert.rejects(upload({ token: 'vc_x', result, fetchImpl: refused }), /402.*not active/);
});
