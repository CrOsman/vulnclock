import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
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

test('the upload command ends on its own with 0 when accepted and 2 when refused', { timeout: 30000 }, async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnclock-cli-'));
    fs.writeFileSync(path.join(dir, 'cra-findings.json'), JSON.stringify(result));
    fs.writeFileSync(path.join(dir, 'sbom.cdx.json'), JSON.stringify({ bomFormat: 'CycloneDX', components: [] }));
    const server = http.createServer((req, res) => {
        req.resume();
        req.on('end', () => {
            const ok = req.headers.authorization === 'Bearer vc_good';
            res.writeHead(ok ? 201 : 401, { 'content-type': 'application/json' });
            res.end(JSON.stringify(ok ? { new: 0, exploited: 0, gone: 2 } : { message: 'Unknown token.' }));
        });
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const run = (token) => new Promise((resolve) => {
        const child = spawn(process.execPath, [fileURLToPath(new URL('../bin/vulnclock.mjs', import.meta.url)), 'upload'], {
            cwd: dir,
            env: { ...process.env, VULNCLOCK_TOKEN: token, VULNCLOCK_URL: `http://127.0.0.1:${server.address().port}/api/v1/scans` },
        });
        let out = '';
        child.stdout.on('data', (d) => (out += d));
        child.stderr.on('data', (d) => (out += d));
        child.on('close', (code) => resolve({ code, out }));
    });
    try {
        const accepted = await run('vc_good');
        assert.equal(accepted.code, 0, accepted.out);
        assert.match(accepted.out, /2 no longer reported/);
        const refused = await run('vc_bad');
        assert.equal(refused.code, 2, refused.out);
        assert.match(refused.out, /401.*Unknown token/);
    } finally {
        server.close();
    }
});
