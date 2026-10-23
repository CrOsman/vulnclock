// Upload of a check (findings + SBOM) to VulnClock Pro, with the product's upload token.
// Nothing is uploaded unless a token is given; the token is only sent in the Authorization header.

export const DEFAULT_URL = 'https://app.vulnclock.com/api/v1/scans';

export async function upload({ url = DEFAULT_URL, token, result, sbom, meta = {}, fetchImpl = fetch }) {
    if (!token) throw new Error('no VulnClock token (set VULNCLOCK_TOKEN)');
    if (!/^https:\/\//.test(url) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\//.test(url)) throw new Error(`the upload address must use https: ${url}`);
    const body = {
        result,
        ...(sbom ? { sbom } : {}),
        ...Object.fromEntries(Object.entries({
            version: meta.version || result?.product?.version,
            ref: meta.ref,
            commit: meta.commit,
            run_url: meta.runUrl,
        }).filter(([, v]) => v)),
    };
    const res = await fetchImpl(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json', authorization: `Bearer ${token}`, 'user-agent': 'vulnclock' },
        body: JSON.stringify(body),
    });
    const text = await res.text();
    let data = {};
    try { data = JSON.parse(text); } catch { /* not JSON */ }
    if (!res.ok) throw new Error(`VulnClock refused the upload (${res.status}): ${data.message || text.slice(0, 200)}`);
    return data;
}
