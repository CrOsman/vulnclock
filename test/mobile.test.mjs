import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { gradleComponents, cocoapodsComponents, spmComponents } from '../lib/mobile.mjs';
import { detectEcosystems, generateSbom } from '../lib/sbom.mjs';
import { scan, podGitSource } from '../lib/scan.mjs';
import { toMarkdown } from '../lib/report.mjs';

const made = [];
after(() => made.forEach((d) => fs.rmSync(d, { recursive: true, force: true })));

function project(files) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnclock-test-'));
    made.push(dir);
    for (const [name, content] of Object.entries(files)) {
        const file = path.join(dir, name);
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content));
    }
    return dir;
}

const purls = (components) => components.map((c) => c.purl).sort();

// A Capacitor app: app module, the Capacitor runtime and a plugin from node_modules, ext variables, a version catalog.
const capacitorAndroid = {
    'android/settings.gradle': [
        "include ':app'",
        "include ':capacitor-android'",
        "project(':capacitor-android').projectDir = new File('../node_modules/@capacitor/android/capacitor')",
        "apply from: 'capacitor.settings.gradle'",
    ].join('\n'),
    'android/capacitor.settings.gradle': [
        "include ':capacitor-app'",
        "project(':capacitor-app').projectDir = new File('../node_modules/@capacitor/app/android')",
    ].join('\n'),
    'android/variables.gradle': "ext {\n    androidxAppCompatVersion = '1.7.0'\n    androidxCoreVersion = '1.16.0'\n}\n",
    'android/build.gradle': "apply from: \"variables.gradle\"\n",
    'android/gradle/libs.versions.toml': '[versions]\nktx = "1.13.1"\n\n[libraries]\nandroidx-core-ktx = { group = "androidx.core", name = "core-ktx", version.ref = "ktx" }\n',
    'android/app/build.gradle': [
        'dependencies {',
        '    implementation "androidx.appcompat:appcompat:$androidxAppCompatVersion"',
        '    implementation libs.androidx.core.ktx',
        "    implementation project(':capacitor-android')",
        "    implementation fileTree(include: ['*.jar'], dir: 'libs')",
        '    testImplementation "junit:junit:4.13.2"',
        '}',
    ].join('\n'),
    'node_modules/@capacitor/android/capacitor/build.gradle': "dependencies {\n    api \"androidx.webkit:webkit:1.12.1\"\n}\n",
    'node_modules/@capacitor/app/android/build.gradle': [
        'ext {',
        "    androidxCoreVersion = project.hasProperty('androidxCoreVersion') ? rootProject.ext.androidxCoreVersion : '1.15.0'",
        '}',
        'dependencies {',
        '    if (System.getenv("CAP_PLUGIN_PUBLISH") == "true") {',
        '        implementation "com.capacitorjs:core:$capacitorVersion"',
        '    } else {',
        "        implementation project(':capacitor-android')",
        '    }',
        '    implementation "androidx.core:core:$androidxCoreVersion"',
        '}',
    ].join('\n'),
};

test('Gradle: declared dependencies of every module, with variables, plugin defaults and the version catalog', () => {
    const warnings = [];
    const dir = project(capacitorAndroid);
    assert.deepEqual(purls(gradleComponents(dir, (m) => warnings.push(m))), [
        'pkg:maven/androidx.appcompat/appcompat@1.7.0',
        'pkg:maven/androidx.core/core-ktx@1.13.1',
        'pkg:maven/androidx.core/core@1.16.0', // the root project's version wins over the plugin default
        'pkg:maven/androidx.webkit/webkit@1.12.1',
    ]);
    assert.deepEqual(warnings, []); // com.capacitorjs:core is only for publishing the plugin
});

test('Gradle: gradle.lockfile, when present, is the list (runtime classpath only)', () => {
    const dir = project({
        'android/settings.gradle': "include ':app'",
        'android/app/build.gradle': 'dependencies { implementation "a:b:1" }',
        'android/app/gradle.lockfile': [
            '# Gradle lock file',
            'androidx.annotation:annotation:1.8.0=debugRuntimeClasspath,releaseRuntimeClasspath',
            'junit:junit:4.13.2=testRuntimeClasspath',
            'empty=',
        ].join('\n'),
    });
    assert.deepEqual(purls(gradleComponents(dir)), ['pkg:maven/androidx.annotation/annotation@1.8.0']);
});

test('Gradle: comments, debug and test configurations, BOM-managed and dynamic versions, map notation, bundles, Kotlin DSL', () => {
    const warnings = [];
    const dir = project({
        'android/settings.gradle.kts': 'include(":app")\n// include(":old")\n',
        'android/gradle.properties': 'okhttpVersion=4.12.0\n# comment=1\n',
        'android/gradle/libs.versions.toml': [
            '[versions]',
            'room = { strictly = "2.6.1" }',
            '',
            '[libraries]',
            'room-runtime = { module = "androidx.room:room-runtime", version.ref = "room" }',
            'room-ktx = { group = "androidx.room", name = "room-ktx", version = { ref = "room" } }',
            'firebase-analytics = { module = "com.google.firebase:firebase-analytics" }',
            '',
            '[bundles]',
            'room = [',
            '  "room-runtime",',
            '  "room-ktx",',
            ']',
        ].join('\n'),
        'android/app/build.gradle.kts': [
            'dependencies {',
            '    implementation(platform("com.google.firebase:firebase-bom:33.5.1"))',
            '    implementation(libs.firebase.analytics)',
            '    implementation(libs.bundles.room)',
            '    implementation("com.squareup.okhttp3:okhttp:${rootProject.ext.okhttpVersion}")',
            '    implementation(group = "com.google.code.gson", name = "gson", version = "2.11.0")',
            '    implementation(kotlin("stdlib", "2.0.21"))',
            '    releaseImplementation("com.example:release-only:1.0.0")',
            '    implementation("com.example:dynamic:1.+")',
            '    // implementation("com.example:commented:1.0.0")',
            '    /* implementation("com.example:block-commented:1.0.0") */',
            '    debugImplementation("com.example:debug-only:1.0.0")',
            '    testImplementation("junit:junit:4.13.2")',
            '    androidTestImplementation("androidx.test:runner:1.6.2")',
            '    compileOnly("com.example:compile-only:1.0.0")',
            '    kapt("androidx.room:room-compiler:2.6.1")',
            '}',
        ].join('\n'),
    });
    assert.deepEqual(purls(gradleComponents(dir, (m) => warnings.push(m))), [
        'pkg:maven/androidx.room/room-ktx@2.6.1',
        'pkg:maven/androidx.room/room-runtime@2.6.1',
        'pkg:maven/com.example/dynamic',
        'pkg:maven/com.example/release-only@1.0.0',
        'pkg:maven/com.google.code.gson/gson@2.11.0',
        'pkg:maven/com.google.firebase/firebase-analytics',
        'pkg:maven/com.squareup.okhttp3/okhttp@4.12.0',
        'pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@2.0.21',
    ]);
    assert.ok(warnings.some((w) => /BOM.*firebase-analytics/.test(w)));
    assert.ok(warnings.some((w) => /dynamic versions.*com\.example:dynamic:1\.\+/.test(w)));
});

test('Gradle: unresolved variables and React Native autolinking are reported', () => {
    const warnings = [];
    const dir = project({
        'android/settings.gradle': "apply from: file('../node_modules/@react-native-community/cli-platform-android/native_modules.gradle'); applyNativeModulesSettingsGradle(settings)\ninclude ':app'\n",
        'android/app/build.gradle': 'dependencies {\n    implementation "com.facebook.react:react-android:$reactNativeVersion"\n}\n',
    });
    assert.deepEqual(purls(gradleComponents(dir, (m) => warnings.push(m))), ['pkg:maven/com.facebook.react/react-android']);
    assert.ok(warnings.some((w) => /autolinking/.test(w)));
    assert.ok(warnings.some((w) => /not resolved.*react-android/.test(w)));
});

test('CocoaPods: Podfile.lock, subspecs merged, npm and git sources, own local pods left out', () => {
    const dir = project({
        'ios/App/Podfile': "pod 'Capacitor'\n",
        'ios/App/Podfile.lock': [
            'PODS:',
            '  - Capacitor (7.4.0):',
            '    - CapacitorCordova',
            '  - CapacitorCordova (7.4.0)',
            '  - "GoogleUtilities/Environment (8.1.0)":',
            '    - GoogleUtilities/Privacy',
            '  - "GoogleUtilities/Privacy (8.1.0)"',
            '  - MyLocalPod (0.1.0)',
            '  - Charts (5.1.0)',
            '',
            'DEPENDENCIES:',
            '  - Capacitor (from `../../node_modules/@capacitor/ios`)',
            '',
            'EXTERNAL SOURCES:',
            '  Capacitor:',
            '    :path: "../../node_modules/@capacitor/ios"',
            '  CapacitorCordova:',
            '    :path: "../../node_modules/@capacitor/ios"',
            '  MyLocalPod:',
            '    :path: "../LocalPods/MyLocalPod"',
            '  Charts:',
            '    :git: https://github.com/danielgindi/Charts.git',
            '    :tag: v5.1.0',
            '',
            'COCOAPODS: 1.16.2',
        ].join('\n'),
    });
    const components = cocoapodsComponents(dir);
    assert.deepEqual(purls(components), [
        'pkg:cocoapods/Capacitor@7.4.0',
        'pkg:cocoapods/CapacitorCordova@7.4.0',
        'pkg:cocoapods/Charts@5.1.0',
        'pkg:cocoapods/GoogleUtilities@8.1.0',
    ]);
    const p = (name, key) => components.find((c) => c.name === name).properties.find((x) => x.name === key)?.value;
    assert.equal(p('Capacitor', 'vulnclock:npm-package'), '@capacitor/ios');
    assert.equal(p('Charts', 'vulnclock:git'), 'https://github.com/danielgindi/Charts.git');
    assert.equal(p('GoogleUtilities', 'vulnclock:subspecs'), 'Environment,Privacy');
});

test('CocoaPods without Podfile.lock: local pods from node_modules and pinned pods have versions, the rest is reported', () => {
    const warnings = [];
    const dir = project({
        'ios/App/Podfile': [
            "  pod 'Capacitor', :path => '../../node_modules/@capacitor/ios'",
            "  pod 'Alamofire', '5.9.1'",
            "  pod 'SDWebImage', '= 5.19.0'",
            "  pod 'FirebaseMessaging'",
            "  pod 'Kingfisher', '~> 7.0'",
            "  pod 'MyOwn', :path => '../LocalPods/MyOwn'",
        ].join('\n'),
        'node_modules/@capacitor/ios/package.json': { name: '@capacitor/ios', version: '7.4.0' },
    });
    assert.deepEqual(purls(cocoapodsComponents(dir, (m) => warnings.push(m))), [
        'pkg:cocoapods/Alamofire@5.9.1',
        'pkg:cocoapods/Capacitor@7.4.0',
        'pkg:cocoapods/FirebaseMessaging',
        'pkg:cocoapods/Kingfisher', // a range is not a version
        'pkg:cocoapods/SDWebImage@5.19.0',
    ]);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /FirebaseMessaging, Kingfisher \('~> 7\.0'\).*ios\/App\/Podfile\.lock/);
});

test('Swift Package Manager: Package.resolved v1 and v2', () => {
    const v2 = project({
        'ios/App/App.xcworkspace/xcshareddata/swiftpm/Package.resolved': {
            pins: [{ identity: 'capacitor-swift-pm', kind: 'remoteSourceControl', location: 'https://github.com/ionic-team/capacitor-swift-pm.git', state: { revision: 'abc', version: '8.5.2' } }],
            version: 2,
        },
    });
    assert.deepEqual(purls(spmComponents(v2)), ['pkg:swift/github.com/ionic-team/capacitor-swift-pm@8.5.2']);
    const v1 = project({
        'ios/Package.resolved': { object: { pins: [{ package: 'Alamofire', repositoryURL: 'https://github.com/Alamofire/Alamofire', state: { version: '5.9.1' } }] }, version: 1 },
    });
    assert.deepEqual(purls(spmComponents(v1)), ['pkg:swift/github.com/Alamofire/Alamofire@5.9.1']);
});

test('Swift Package Manager without Package.resolved: exact pins from Package.swift, local packages skipped, ranges reported', () => {
    const warnings = [];
    const dir = project({
        'ios/App/CapApp-SPM/Package.swift': [
            'let package = Package(',
            '    dependencies: [',
            '        .package(url: "https://github.com/ionic-team/capacitor-swift-pm.git", exact: "8.5.2"),',
            '        .package(url: "https://github.com/firebase/firebase-ios-sdk.git", from: "11.0.0"),',
            '        .package(url: "https://github.com/apple/swift-log.git", .exact("1.6.1")),',
            '        .package(',
            '            url: "https://github.com/apple/swift-nio.git",',
            '            exact: "2.65.0"',
            '        ),',
            '        .package(name: "CapacitorApp", path: "../../../node_modules/@capacitor/app")',
            '    ]',
            ')',
        ].join('\n'),
    });
    const components = spmComponents(dir, (m) => warnings.push(m));
    assert.deepEqual(purls(components), [
        'pkg:swift/github.com/apple/swift-log@1.6.1',
        'pkg:swift/github.com/apple/swift-nio@2.65.0',
        'pkg:swift/github.com/firebase/firebase-ios-sdk',
        'pkg:swift/github.com/ionic-team/capacitor-swift-pm@8.5.2',
    ]);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /firebase-ios-sdk/);
});

test('Swift packages added in Xcode, without Package.resolved: exact versions from project.pbxproj', () => {
    const warnings = [];
    const ref = (id, url, requirement) => `\t\t${id} /* XCRemoteSwiftPackageReference */ = {\n\t\t\tisa = XCRemoteSwiftPackageReference;\n\t\t\trepositoryURL = "${url}";\n\t\t\trequirement = {\n${requirement}\t\t\t};\n\t\t};\n`;
    const dir = project({
        'ios/App/App.xcodeproj/project.pbxproj': [
            '/* Begin XCRemoteSwiftPackageReference section */\n',
            ref('A1', 'https://github.com/Alamofire/Alamofire.git', '\t\t\t\tkind = exactVersion;\n\t\t\t\tversion = 5.9.1;\n'),
            ref('A2', 'https://github.com/onevcat/Kingfisher', '\t\t\t\tkind = upToNextMajorVersion;\n\t\t\t\tminimumVersion = 7.0.0;\n'),
            '/* End XCRemoteSwiftPackageReference section */\n',
        ].join(''),
    });
    assert.deepEqual(purls(spmComponents(dir, (m) => warnings.push(m))), ['pkg:swift/github.com/Alamofire/Alamofire@5.9.1', 'pkg:swift/github.com/onevcat/Kingfisher']);
    assert.match(warnings[0], /Kingfisher/);
});

test('a mobile project without npm or Composer: ecosystems are detected and merged into one SBOM', () => {
    const dir = project({
        ...capacitorAndroid,
        'ios/App/App.xcodeproj/project.pbxproj': '',
        'ios/App/Podfile': "pod 'Alamofire', '5.9.1'\n",
    });
    assert.deepEqual(detectEcosystems(dir), ['gradle', 'cocoapods', 'spm']);
    const bom = generateSbom(dir, { name: 'demo', version: '1.0.0' });
    assert.equal(bom.components.length, 5);
    assert.equal(bom.metadata.component.name, 'demo');
    assert.deepEqual(bom.dependencies[0].dependsOn.slice().sort(), purls(bom.components));
    assert.equal(bom.metadata.properties.find((p) => p.name === 'vulnclock:ecosystems').value, 'gradle,cocoapods,spm');
});

test('components without a version are listed as not checked, not queried (no false positives)', async () => {
    const result = await scan({ components: [{ name: 'FirebaseMessaging', purl: 'pkg:cocoapods/FirebaseMessaging' }, { group: 'com.capacitorjs', name: 'core', purl: 'pkg:maven/com.capacitorjs/core' }] }, { kev: false, euvd: false, fetchJson: async () => { throw new Error('no network in this test'); } });
    assert.equal(result.components, 0);
    assert.deepEqual(result.unversioned, ['FirebaseMessaging', 'com.capacitorjs/core']);
    assert.equal(result.counts.total, 0);
    assert.match(toMarkdown(result), /Not checked \(version unknown\):\*\* FirebaseMessaging, com\.capacitorjs\/core/);
});

// A stand-in for OSV.dev: one advisory for capacitor-swift-pm 8.5.2 (Swift) and one for @capacitor/ios 7.4.0 (npm).
function fakeOsv(queried) {
    const vulns = {
        'pkg:swift/github.com/ionic-team/capacitor-swift-pm@8.5.2': 'GHSA-swift',
        'pkg:npm/%40capacitor/ios@7.4.0': 'GHSA-npm',
    };
    return async (url, init) => {
        if (url.endsWith('/querybatch')) {
            const queries = JSON.parse(init.body).queries.map((q) => q.package.purl);
            queried.push(...queries);
            return { results: queries.map((p) => (vulns[p] ? { vulns: [{ id: vulns[p] }] } : {})) };
        }
        const id = decodeURIComponent(url.split('/vulns/')[1]);
        const purl = Object.keys(vulns).find((p) => vulns[p] === id);
        return { id, aliases: [], summary: `test ${id}`, database_specific: { severity: 'HIGH' }, affected: [{ package: { purl: purl.split('@').slice(0, -1).join('@') }, ranges: [{ events: [{ introduced: '0' }, { fixed: '9.0.0' }] }] }] };
    };
}

test('CocoaPods pods are checked as their npm package or their git repository; pods without either are listed as not covered', async () => {
    const queried = [];
    const pod = (name, version, props = []) => ({ name, version, purl: `pkg:cocoapods/${name}@${version}`, 'bom-ref': `pkg:cocoapods/${name}@${version}`, properties: props });
    const bom = {
        components: [
            { name: '@capacitor/app', version: '7.0.0', purl: 'pkg:npm/%40capacitor/app@7.0.0', 'bom-ref': 'a' },
            pod('CapacitorApp', '7.0.0', [{ name: 'vulnclock:npm-package', value: '@capacitor/app' }]), // already checked as npm
            pod('Capacitor', '7.4.0', [{ name: 'vulnclock:npm-package', value: '@capacitor/ios' }]), // npm package not in the BOM
            pod('CapacitorSwiftPM', '8.5.2'), // found through the podspec
            pod('NoSource', '1.0.0'),
            { name: 'thing', version: '1', purl: 'pkg:generic/thing@1', 'bom-ref': 'g' },
        ],
    };
    const podSource = async (name) => (name === 'CapacitorSwiftPM' ? 'https://github.com/ionic-team/capacitor-swift-pm.git' : null);
    const result = await scan(bom, { kev: false, euvd: false, fetchJson: fakeOsv(queried), podSource });
    assert.deepEqual(queried.sort(), ['pkg:npm/%40capacitor/app@7.0.0', 'pkg:npm/%40capacitor/ios@7.4.0', 'pkg:swift/github.com/ionic-team/capacitor-swift-pm@8.5.2']);
    assert.equal(result.components, 4);
    assert.deepEqual(result.uncovered.sort(), ['NoSource', 'thing']);
    assert.deepEqual(result.findings.map((f) => [f.id, f.component, f.checkedAs, f.fixed.join()]).sort(), [
        ['GHSA-npm', 'Capacitor', 'npm @capacitor/ios', '9.0.0'],
        ['GHSA-swift', 'CapacitorSwiftPM', 'github.com/ionic-team/capacitor-swift-pm', '9.0.0'],
    ]);
    const md = toMarkdown(result);
    assert.match(md, /no vulnerability database covers them\):\*\* NoSource, thing|no vulnerability database covers them\):\*\* thing, NoSource/);
    assert.match(md, /CapacitorSwiftPM \(checked as github\.com\/ionic-team\/capacitor-swift-pm\)/);
});

test('the podspec lookup uses the CocoaPods CDN layout', async () => {
    let asked = '';
    const git = await podGitSource('AFNetworking', '2.5.1', async (url) => { asked = url; return { source: { git: 'https://github.com/AFNetworking/AFNetworking.git', tag: '2.5.1' } }; });
    assert.equal(asked, 'https://cdn.cocoapods.org/Specs/a/7/5/AFNetworking/2.5.1/AFNetworking.podspec.json');
    assert.equal(git, 'https://github.com/AFNetworking/AFNetworking.git');
});
