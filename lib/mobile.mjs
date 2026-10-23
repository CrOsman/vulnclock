// SBOM components of Android and iOS apps, read from the build files without running a build.
//
// Gradle: the declared dependencies of every module in settings.gradle (including Capacitor / Cordova plugin
// modules that live in node_modules), versions resolved from ext variables, gradle.properties, plugin defaults and
// version catalogs. That is the top-level dependency list the CRA asks for at the very least (Annex I, Part II, 1);
// a gradle.lockfile, when the project uses dependency locking, gives the full release runtime list instead.
// iOS: Podfile.lock (CocoaPods), Package.resolved (Swift Package Manager). Without them only what has a fixed version
// can be checked: local pods from node_modules, pinned pods, exact pins in Package.swift or the Xcode project.
//
// A component whose version is unknown is still listed (without a version), so the report can name it.

import fs from 'node:fs';
import path from 'node:path';

const read = (f) => fs.readFileSync(f, 'utf8');
const exists = (f) => fs.existsSync(f);
const SKIP_DIRS = new Set(['node_modules', '.git', 'build', '.build', '.gradle', 'Pods', 'DerivedData', 'SourcePackages']);

function walk(dir, test, out = [], depth = 0) {
    if (depth > 6 || !exists(dir)) return out;
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        if (SKIP_DIRS.has(e.name)) continue;
        const p = path.join(dir, e.name);
        if (e.isDirectory()) walk(p, test, out, depth + 1);
        else if (test(e.name, p)) out.push(p);
    }
    return out;
}

const prop = (name, value) => ({ name, value });

function mavenComponent(group, name, version, properties = []) {
    const purl = `pkg:maven/${group}/${name}${version ? `@${version}` : ''}`;
    return { type: 'library', 'bom-ref': purl, group, name, ...(version ? { version } : {}), purl, properties };
}

// ---------- Gradle ----------

export function androidRoot(dir) {
    for (const d of [dir, path.join(dir, 'android')]) {
        if (['settings.gradle', 'settings.gradle.kts'].some((f) => exists(path.join(d, f)))) return d;
    }
    return null;
}

function closingBrace(s, open) {
    let depth = 0;
    for (let i = open; i < s.length; i++) {
        if (s[i] === '{') depth++;
        else if (s[i] === '}' && --depth === 0) return i;
    }
    return s.length - 1;
}

// Without comments, and without the branch Capacitor plugins use only to publish themselves:
// if (System.getenv("CAP_PLUGIN_PUBLISH") == "true") { com.capacitorjs:core } else { project(':capacitor-android') }
function cleanGradle(src) {
    let s = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:"'\\])\/\/.*$/gm, '$1');
    for (let m; (m = /if\s*\(.*CAP_PLUGIN_PUBLISH.*\)\s*\{/.exec(s));) {
        const end = closingBrace(s, m.index + m[0].length - 1);
        const els = /^\s*else\s*\{/.exec(s.slice(end + 1));
        if (els) {
            const open = end + els[0].length;
            const close = closingBrace(s, open);
            s = s.slice(0, m.index) + s.slice(open + 1, close) + s.slice(close + 1);
        } else {
            s = s.slice(0, m.index) + s.slice(end + 1);
        }
    }
    return s;
}

// name = 'x', ext.name = "x", def name = 'x', val name = "x", and plugin defaults: name = project.hasProperty('n') ? rootProject.ext.n : 'x'
function collectVariables(files) {
    const vars = {};
    const defaults = {};
    for (const f of files) {
        const src = cleanGradle(read(f));
        for (const m of src.matchAll(/^\s*(?:ext\.|def\s+|val\s+)?(\w+)\s*=\s*["']([^"'$]+)["']\s*$/gm)) vars[m[1]] = m[2];
        for (const m of src.matchAll(/(\w+)\s*=\s*project\.hasProperty\(\s*["']\w+["']\s*\)\s*\?\s*rootProject\.ext\.\w+\s*:\s*["']([^"']+)["']/g)) {
            if (!(m[1] in defaults)) defaults[m[1]] = m[2];
        }
    }
    return { vars, defaults };
}

function gradleProperties(root) {
    const file = path.join(root, 'gradle.properties');
    const out = {};
    if (exists(file)) for (const m of read(file).matchAll(/^[ \t]*([\w.-]+)[ \t]*[=:][ \t]*(\S.*?)[ \t]*$/gm)) out[m[1]] = m[2];
    return out;
}

const accessor = (key) => key.replace(/[-_]/g, '.');

// gradle/libs.versions.toml -> { libs: accessor -> "group:name:version", bundles: accessor -> [library accessors] }
function readCatalog(root) {
    const file = path.join(root, 'gradle', 'libs.versions.toml');
    const libs = {};
    const bundles = {};
    if (!exists(file)) return { libs, bundles };
    const text = read(file).replace(/#.*$/gm, '');
    const section = (name) => (text.match(new RegExp(`^\\[${name}\\][ \\t]*$([\\s\\S]*?)(?=^\\[|(?![\\s\\S]))`, 'm')) || [])[1] || '';
    const quoted = (s, key) => (s.match(new RegExp(`(?<![.\\w])${key}\\s*=\\s*["']([^"']+)["']`)) || [])[1];

    const versions = {};
    for (const m of section('versions').matchAll(/^\s*([\w.-]+)\s*=\s*(.+?)\s*$/gm)) {
        const v = m[2];
        versions[m[1]] = /^["']/.test(v) ? v.replace(/^["']|["']$/g, '') : quoted(v, 'strictly') || quoted(v, 'require') || quoted(v, 'prefer') || '';
    }
    for (const m of section('libraries').matchAll(/^\s*([\w.-]+)\s*=\s*(.+?)\s*$/gm)) {
        const value = m[2];
        const str = value.match(/^["']([^"']+)["']$/);
        if (str) { libs[accessor(m[1])] = str[1]; continue; }
        const module = quoted(value, 'module');
        const group = quoted(value, 'group');
        const name = quoted(value, 'name');
        const coords = module || (group && name ? `${group}:${name}` : null);
        if (!coords) continue;
        const ref = (value.match(/version\s*(?:\.\s*ref\s*=|=\s*\{\s*ref\s*=)\s*["']([^"']+)["']/) || [])[1];
        const rich = (value.match(/version\s*=\s*\{([^}]*)\}/) || [])[1];
        const version = ref ? versions[ref] || '' : rich ? quoted(rich, 'strictly') || quoted(rich, 'require') || quoted(rich, 'prefer') || '' : quoted(value, 'version') || '';
        libs[accessor(m[1])] = `${coords}:${version}`;
    }
    for (const m of section('bundles').matchAll(/^\s*([\w.-]+)\s*=\s*\[([^\]]*)\]/gm)) {
        bundles[accessor(m[1])] = [...m[2].matchAll(/["']([^"']+)["']/g)].map((x) => accessor(x[1]));
    }
    return { libs, bundles };
}

// Modules from settings.gradle (and files it applies, e.g. capacitor.settings.gradle) -> their directories
function gradleModules(root, warn) {
    const modules = new Map();
    const visit = (file) => {
        if (!exists(file)) return;
        const src = cleanGradle(read(file));
        for (const m of src.matchAll(/(?:^|[\s;])include\s*\(?\s*((?:["'][^"']+["']\s*,?\s*)+)\)?/gm)) {
            for (const n of m[1].matchAll(/["']:?([^"']+)["']/g)) if (!modules.has(n[1])) modules.set(n[1], path.join(root, n[1].replace(/:/g, path.sep)));
        }
        for (const m of src.matchAll(/project\(\s*["']:?([^"']+)["']\s*\)\.projectDir\s*=\s*(?:new\s+)?[Ff]ile\(\s*(?:(?:settingsDir|rootDir|rootProject\.projectDir)\s*,\s*)?["']([^"']+)["']\s*\)/g)) {
            modules.set(m[1], path.resolve(root, m[2]));
        }
        for (const m of src.matchAll(/apply\s*\(?\s*from\s*[:=]\s*(?:file\(\s*)?["']([^"']+)["']/g)) visit(path.resolve(path.dirname(file), m[1]));
        if (/applyNativeModulesSettingsGradle|autolinkLibrariesFromCommand|com\.facebook\.react\.settings|dev\.flutter\.flutter-plugin-loader/.test(src)) {
            warn('Plugin modules of this Android project are added at build time (React Native autolinking or Flutter): their native dependencies are not in the SBOM. Use dependency locking (gradle.lockfile) or an SBOM from the build.');
        }
    };
    visit(exists(path.join(root, 'settings.gradle')) ? path.join(root, 'settings.gradle') : path.join(root, 'settings.gradle.kts'));
    return modules;
}

// Only what the release app runs with: runtimeClasspath, releaseRuntimeClasspath, <flavor>ReleaseRuntimeClasspath.
const RELEASE_CLASSPATH = /^(\w*[rR]elease)?[rR]untimeClasspath$/;

function parseLockfiles(root) {
    const out = new Map();
    for (const f of walk(root, (n) => n === 'gradle.lockfile')) {
        for (const line of read(f).split(/\r?\n/)) {
            const m = line.match(/^([^:#\s]+):([^:\s]+):([^=\s]+)=(.+)$/);
            if (!m || !m[4].split(',').some((c) => RELEASE_CLASSPATH.test(c.trim()))) continue;
            const c = mavenComponent(m[1], m[2], m[3], [prop('vulnclock:source', 'gradle.lockfile')]);
            out.set(c.purl, c);
        }
    }
    return [...out.values()];
}

// Configurations whose dependencies end up in the release app (flavours and build types included, debug and tests not).
const DEPENDENCY = /(?:^|[\s{;])(implementation|api|runtimeOnly|compile|[a-z]\w*(?:Implementation|Api|RuntimeOnly))\b[ \t]*\(?[ \t]*([^\n;]*)/gm;
const NOT_SHIPPED = /^(test|androidTest|debug|testFixtures|compileOnly|lintChecks|kapt|ksp|annotationProcessor)/;

// "group:name:version" strings of one dependency declaration ('!libs.x' when a catalog entry is missing)
function dependencyCoords(arg, catalog) {
    const a = arg.trim();
    if (/^(project|fileTree|files|platform|enforcedPlatform|testFixtures)\s*\(/.test(a)) return [];
    const kt = a.match(/^kotlin\s*\(\s*["']([\w.-]+)["']\s*(?:,\s*["']([^"']+)["'])?/);
    if (kt) return [`org.jetbrains.kotlin:kotlin-${kt[1]}:${kt[2] || ''}`];
    const field = (k) => (a.match(new RegExp(`\\b${k}\\s*[:=]\\s*["']([^"']+)["']`)) || [])[1];
    if (field('group') && field('name')) return [`${field('group')}:${field('name')}:${field('version') || ''}`];
    const lit = a.match(/["']([\w.-]+:[\w.-]+(?::[^"'\s]*)?)["']/);
    if (lit) return [lit[1]];
    const bundle = a.match(/\blibs\.bundles\.([\w.]+)/);
    if (bundle) return catalog.bundles[bundle[1]] ? catalog.bundles[bundle[1]].map((k) => catalog.libs[k] || `!libs.${k}`) : [`!libs.bundles.${bundle[1]}`];
    const lib = a.match(/\blibs\.([\w.]+?)(?:\.get\(\))?(?![\w.])/);
    if (lib) return [catalog.libs[lib[1]] || `!libs.${lib[1]}`];
    return [];
}

export function gradleComponents(dir, warn = () => {}) {
    const root = androidRoot(dir);
    if (!root) return [];
    const locked = parseLockfiles(root);
    if (locked.length) return locked;

    const modules = gradleModules(root, warn);
    const rootFiles = ['build.gradle', 'build.gradle.kts', 'variables.gradle'].map((f) => path.join(root, f)).filter(exists);
    const moduleFiles = [...modules.values()].flatMap((d) => [path.join(d, 'build.gradle'), path.join(d, 'build.gradle.kts')]).filter(exists);
    const { vars, defaults } = collectVariables([...moduleFiles, ...rootFiles]);
    const rootVars = { ...gradleProperties(root), ...collectVariables(rootFiles).vars };
    const lookup = (n) => rootVars[n] ?? defaults[n] ?? vars[n];
    // $name, ${name}, ${rootProject.ext.name}, ${project.name}
    const resolve = (v) => v.replace(/\$\{([\w.]+)\}|\$(\w+)/g, (all, a, b) => lookup((a || b).split('.').pop()) ?? all);
    const catalog = readCatalog(root);

    const found = new Map();
    const unresolved = new Set();
    const managed = new Set();
    const dynamic = new Set();
    const missing = new Set();
    for (const [name, moduleDir] of modules) {
        const file = [path.join(moduleDir, 'build.gradle'), path.join(moduleDir, 'build.gradle.kts')].find(exists);
        if (!file) {
            if (name !== 'capacitor-cordova-android-plugins') warn(`Gradle module :${name} has no build file at ${moduleDir} (run npm install / cap sync first?)`);
            continue;
        }
        for (const m of cleanGradle(read(file)).matchAll(DEPENDENCY)) {
            if (NOT_SHIPPED.test(m[1])) continue;
            for (const coords of dependencyCoords(m[2], catalog)) {
                if (coords.startsWith('!')) { missing.add(coords.slice(1)); continue; }
                const [group, artifact, raw = ''] = resolve(coords).split(':');
                if (!group || !artifact || group.includes('$') || artifact.includes('$')) continue;
                let version = raw.replace(/@\w+$/, '');
                const id = `${group}:${artifact}`;
                if (version.includes('$')) { unresolved.add(id); version = ''; }
                else if (/[+[\]()]|^latest\./.test(version)) { dynamic.add(`${id}:${version}`); version = ''; }
                else if (!version) managed.add(id);
                const key = `${id}:${version}`;
                if (!found.has(key)) found.set(key, mavenComponent(group, artifact, version, [prop('vulnclock:gradle-module', name), prop('vulnclock:source', 'declared dependency')]));
            }
        }
    }
    if (unresolved.size) warn(`Gradle versions not resolved (listed, not checked): ${[...unresolved].join(', ')}`);
    if (managed.size) warn(`Gradle dependencies without a version, set by a BOM / platform or constraints (listed, not checked): ${[...managed].join(', ')}. Dependency locking (gradle.lockfile) gives their versions.`);
    if (dynamic.size) warn(`Gradle dynamic versions (listed, not checked): ${[...dynamic].join(', ')}. Use fixed versions or dependency locking.`);
    if (missing.size) warn(`Not in gradle/libs.versions.toml: ${[...missing].join(', ')}`);
    return [...found.values()];
}

// ---------- iOS ----------

export function iosRoots(dir) {
    return [dir, path.join(dir, 'ios'), path.join(dir, 'ios', 'App')].filter((d) => exists(d));
}

// "../../node_modules/@capacitor/app" -> "@capacitor/app"
function npmPackageOf(p) {
    const m = String(p).replace(/\\/g, '/').match(/node_modules\/((?:@[^/]+\/)?[^/]+)\/?/);
    return m ? m[1] : null;
}

function podComponent(pod, version, source, extra = []) {
    const purl = `pkg:cocoapods/${pod}${version ? `@${version}` : ''}`;
    return { type: 'library', 'bom-ref': purl, name: pod, ...(version ? { version } : {}), purl, properties: [prop('vulnclock:source', source), ...extra] };
}

// One component per pod and version; subspecs (Firebase/Messaging) are the same code base.
function parsePodfileLock(file) {
    const pods = new Map();
    const external = new Map();
    let section = '';
    let current = null;
    for (const line of read(file).split(/\r?\n/)) {
        const top = line.match(/^([A-Z][A-Z ]+):\s*$/);
        if (top) { section = top[1]; current = null; continue; }
        if (section === 'PODS') {
            const m = line.match(/^ {2}- "?([^\s"(]+) \(([^)]+)\)"?:?$/);
            if (m) {
                const [pod, sub] = m[1].split('/');
                const key = `${pod}@${m[2]}`;
                if (!pods.has(key)) pods.set(key, { pod, version: m[2], subspecs: new Set() });
                if (sub) pods.get(key).subspecs.add(sub);
            }
        } else if (section === 'EXTERNAL SOURCES' || section === 'CHECKOUT OPTIONS') {
            const name = line.match(/^ {2}"?([^\s":]+)"?:\s*$/);
            if (name) { current = name[1]; if (!external.has(current)) external.set(current, {}); continue; }
            const kv = current && line.match(/^ {4}:(\w+):\s*"?([^"]+?)"?\s*$/);
            if (kv) external.get(current)[kv[1]] = kv[2];
        }
    }
    return [...pods.values()].flatMap(({ pod, version, subspecs }) => {
        const ext = external.get(pod) || {};
        if (ext.path && !npmPackageOf(ext.path)) return []; // a local pod in the repository is the product's own code
        const extra = [];
        if (ext.path) extra.push(prop('vulnclock:npm-package', npmPackageOf(ext.path)));
        if (ext.git) extra.push(prop('vulnclock:git', ext.git));
        if (subspecs.size) extra.push(prop('vulnclock:subspecs', [...subspecs].sort().join(',')));
        return [podComponent(pod, version, 'Podfile.lock', extra)];
    });
}

export function cocoapodsComponents(dir, warn = () => {}) {
    const lock = iosRoots(dir).map((d) => path.join(d, 'Podfile.lock')).find(exists);
    if (lock) return parsePodfileLock(lock);
    const podfile = iosRoots(dir).map((d) => path.join(d, 'Podfile')).find(exists);
    if (!podfile) return [];
    // No lock file: local pods (Capacitor plugins from node_modules) carry their package.json version and exact pins
    // are known; pods without a version or with a range ('~> 11.0') are listed without a version.
    const out = new Map();
    const unknown = [];
    for (const m of read(podfile).matchAll(/^\s*pod\s+["']([^"']+)["']\s*(?:,\s*(.+))?$/gm)) {
        const pod = m[1].split('/')[0];
        const opts = m[2] || '';
        const local = opts.match(/:path\s*=>\s*["']([^"']+)["']/);
        const git = opts.match(/:git\s*=>\s*["']([^"']+)["']/);
        const tag = opts.match(/:tag\s*=>\s*["']v?([^"']+)["']/);
        const pin = opts.match(/^["']\s*(?:=\s*)?(\d[\w.-]*)\s*["']/);
        let c;
        if (local) {
            const npm = npmPackageOf(local[1]);
            if (!npm) continue; // the product's own code
            const pkg = path.resolve(path.dirname(podfile), local[1], 'package.json');
            const version = exists(pkg) ? JSON.parse(read(pkg)).version : '';
            c = podComponent(pod, version, 'Podfile (local pod)', [prop('vulnclock:npm-package', npm)]);
        } else if (git) {
            c = podComponent(pod, tag ? tag[1] : '', 'Podfile (git)', [prop('vulnclock:git', git[1])]);
        } else {
            c = podComponent(pod, pin ? pin[1] : '', pin ? 'Podfile (pinned)' : 'Podfile (version unknown)');
        }
        if (!c.version) unknown.push(opts.trim() && !local && !git ? `${pod} (${opts.trim()})` : pod);
        out.set(c.purl, c);
    }
    const lockPath = path.relative(dir, path.join(path.dirname(podfile), 'Podfile.lock')).replace(/\\/g, '/');
    if (unknown.length) warn(`No Podfile.lock: versions of ${unknown.join(', ')} are unknown (listed, not checked). Commit ${lockPath} for exact versions.`);
    return [...out.values()];
}

// https://github.com/ionic-team/capacitor-swift-pm.git -> pkg:swift/github.com/ionic-team/capacitor-swift-pm@8.5.2
export function swiftPurl(url, version) {
    const m = String(url).trim().replace(/^git@([^:]+):/, 'https://$1/').match(/^(?:https?|ssh|git):\/\/(?:[^@/]+@)?([^/:]+)(?::\d+)?\/(.+?)(?:\.git)?\/?$/);
    if (!m || !m[2].includes('/')) return null;
    const parts = m[2].split('/');
    const name = parts.pop();
    const group = `${m[1]}/${parts.join('/')}`;
    return { group, name, purl: `pkg:swift/${group}/${name}${version ? `@${version}` : ''}` };
}

function swiftComponent(url, version, source) {
    const id = swiftPurl(url, version);
    return id && { type: 'library', 'bom-ref': id.purl, group: id.group, name: id.name, ...(version ? { version } : {}), purl: id.purl, properties: [prop('vulnclock:source', source)] };
}

export function spmComponents(dir, warn = () => {}) {
    const roots = iosRoots(dir);
    const find = (test) => [...new Set(roots.flatMap((d) => walk(d, test)))];
    const out = new Map();
    const put = (c) => c && !out.has(c.purl) && out.set(c.purl, c);

    const resolved = find((n) => n === 'Package.resolved');
    for (const f of resolved) {
        const data = JSON.parse(read(f));
        for (const pin of data.pins || data.object?.pins || []) put(swiftComponent(pin.location || pin.repositoryURL || '', pin.state?.version || '', 'Package.resolved'));
    }
    if (resolved.length) return [...out.values()];

    // No Package.resolved: Package.swift (e.g. Capacitor 8 CapApp-SPM, resolved only in the iOS build) and Swift
    // packages added in Xcode (project.pbxproj). Only exact pins identify a version; local path packages are npm
    // packages and already come from package-lock.json.
    const ranged = [];
    for (const f of find((n) => n === 'Package.swift')) {
        for (const m of read(f).matchAll(/\.package\(\s*(?:name:\s*"[^"]*"\s*,\s*)?url:\s*"([^"]+)"\s*,((?:[^()]|\([^()]*\))*)\)/g)) {
            const exact = m[2].match(/(?:exact:\s*|\.exact\(\s*)"([^"]+)"/);
            const c = swiftComponent(m[1], exact ? exact[1] : '', exact ? 'Package.swift (exact)' : 'Package.swift (version range)');
            if (c && !exact) ranged.push(`${c.group}/${c.name}`);
            put(c);
        }
    }
    for (const f of find((n) => n === 'project.pbxproj')) {
        for (const m of read(f).matchAll(/isa = XCRemoteSwiftPackageReference;([\s\S]*?requirement = \{[\s\S]*?\};)/g)) {
            const url = (m[1].match(/repositoryURL = "?([^";]+)"?;/) || [])[1];
            const kind = (m[1].match(/kind = (\w+);/) || [])[1];
            const version = kind === 'exactVersion' ? (m[1].match(/version = "?([^";]+)"?;/) || [])[1] : '';
            const c = url && swiftComponent(url, version || '', version ? 'Xcode project (exact)' : `Xcode project (${kind || 'requirement unknown'})`);
            if (c && !version) ranged.push(`${c.group}/${c.name}`);
            put(c);
        }
    }
    if (ranged.length) warn(`No Package.resolved: ${[...new Set(ranged)].join(', ')} have version ranges, branches or revisions (listed, not checked). Commit Package.resolved for exact versions.`);
    return [...out.values()];
}
