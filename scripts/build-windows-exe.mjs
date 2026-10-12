#!/usr/bin/env node
// Windows 向けの単一実行ファイル（.exe）を作る。Node.js の Single Executable Applications（SEA）を使う。
//
//   npm run build:win
//
// 手順:
//   1. TypeScript を CommonJS で出力する（SEA の起点は CommonJS の1ファイルである必要がある）
//   2. 出力を1ファイルにまとめる（依存パッケージ0のため、自前の小さな結合処理で足りる）
//   3. 専用ウィンドウ（native/windows-host/host.cpp）を MinGW-w64 でビルドする。
//      WebView2 SDK（ヘッダーと公式の WebView2Loader.dll）は NuGet から取得し、固定した SHA256 と照合する
//   4. SEA 用のデータ（blob）を作る。専用ウィンドウの部品は assets として入れる。
//      コードキャッシュ・スナップショットは使わない（OSをまたいで同じ blob を使えるように）
//   5. 公式の Windows 用 node.exe（このビルドに使う Node.js と同じバージョン）を nodejs.org から取得し、
//      公式の SHA256 一覧（SHASUMS256.txt）と照合する
//   6. node.exe の Authenticode 署名を外す（中身を書き換えると署名が壊れるため）
//   7. アイコンとバージョン情報を「公開前チェック」のものにし（resedit）、postject で blob を埋め込み、
//      「ウィンドウのアプリ」（黒い画面を開かない）に切り替える
//   8. 動作確認用に、同じ blob を埋め込んだ Linux 版も作る（Windows 版と同じ仕組みで動く）
//
// 必要なもの（ビルドする人だけ）: Node.js 22 以上、MinGW-w64（Ubuntu: apt install g++-mingw-w64-x86-64-win32）
//
// 生成物:
//   release/windows/koukai-check-<version>-win-x64.exe
//   release/windows/SHA256SUMS.txt
//   build/sea/koukai-check-linux-x64（動作確認用。配布しない）

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateRawSync } from 'node:zlib';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BUILD = join(ROOT, 'build', 'sea');
const CJS = join(BUILD, 'cjs');
const CACHE = join(BUILD, 'cache');
const RELEASE = join(ROOT, 'release', 'windows');
const SENTINEL_FUSE = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2';
const HOST_SRC = join(ROOT, 'native', 'windows-host');
const HOST_OUT = join(BUILD, 'windows-host');

// WebView2 SDK（Microsoft 公式。BSD 3-Clause）。版と SHA256 を固定し、違えばビルドを止める
export const WEBVIEW2_SDK = {
  version: '1.0.4129.50',
  sha256: 'd3934f482d484b89fb4825df720c710664e1143a1e90f7b3a60794ef33f473d2',
};

const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
const NODE_VERSION = process.version; // blob を作る Node と、埋め込み先の node.exe のバージョンをそろえる

function log(message) {
  console.log(`[build:win] ${message}`);
}

// ───────────── 1. CommonJS で出力 ─────────────

function compileCjs() {
  rmSync(BUILD, { recursive: true, force: true });
  execFileSync(process.execPath, [join(ROOT, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', join(ROOT, 'tsconfig.sea.json')], { stdio: 'inherit' });
}

// ───────────── 2. 1ファイルに結合 ─────────────

/** cli/index.js から辿れるモジュールを集め、require('./x.js') を内部の参照に置き換えて1ファイルにする */
export function bundleCjs(cjsRoot, entry) {
  const modules = new Map();
  const visit = (id) => {
    if (modules.has(id)) return;
    const file = join(cjsRoot, id);
    let code = readFileSync(file, 'utf8').replace(/^#!.*\n/, '');
    modules.set(id, ''); // 循環参照に備えて先に登録
    code = code.replace(/require\("(\.{1,2}\/[^"]+)"\)/g, (_m, spec) => {
      const target = relative(cjsRoot, resolve(dirname(file), spec)).split(sep).join('/');
      if (target.startsWith('..')) throw new Error(`想定外の require: ${spec} (${id})`);
      visit(target);
      return `__kcRequire(${JSON.stringify(target)})`;
    });
    // node: 以外の require（外部パッケージ）が残っていないことを確かめる（実行時の依存は0のはず）
    for (const m of code.matchAll(/require\("([^"]+)"\)/g)) {
      if (!m[1].startsWith('node:')) throw new Error(`外部モジュールの require: ${m[1]} (${id})`);
    }
    modules.set(id, code);
  };
  visit(entry);

  const parts = [
    '"use strict";',
    `// ${pkg.name} ${pkg.version} — Node.js SEA 用に結合したファイル（自動生成）`,
    'const __kcModules = {',
    ...[...modules.entries()].map(([id, code]) => `${JSON.stringify(id)}: function (module, exports, require, __kcRequire) {\n${code}\n},`),
    '};',
    'const __kcCache = {};',
    'function __kcRequire(id) {',
    '  const cached = __kcCache[id];',
    '  if (cached) return cached.exports;',
    '  const module = { exports: {} };',
    '  __kcCache[id] = module;',
    '  __kcModules[id].call(module.exports, module, module.exports, require, __kcRequire);',
    '  return module.exports;',
    '}',
    `__kcRequire(${JSON.stringify(entry)});`,
  ];
  return { code: parts.join('\n'), moduleCount: modules.size };
}

// ───────────── 3. 専用ウィンドウをビルド ─────────────

/** ZIP（.nupkg）から指定したファイルだけを取り出す。外部ツールを使わないための最小限の読み取り */
export function readZipEntries(zip, names) {
  const out = new Map();
  let eocd = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 65557); i--) {
    if (zip.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('ZIP の形式ではありません');
  const count = zip.readUInt16LE(eocd + 10);
  let p = zip.readUInt32LE(eocd + 16);
  for (let n = 0; n < count; n++) {
    if (zip.readUInt32LE(p) !== 0x02014b50) throw new Error('ZIP の中央ディレクトリが壊れています');
    const method = zip.readUInt16LE(p + 10);
    const compSize = zip.readUInt32LE(p + 20);
    const nameLen = zip.readUInt16LE(p + 28);
    const extraLen = zip.readUInt16LE(p + 30);
    const commentLen = zip.readUInt16LE(p + 32);
    const local = zip.readUInt32LE(p + 42);
    const name = zip.toString('utf8', p + 46, p + 46 + nameLen);
    if (names.includes(name)) {
      const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
      const data = zip.subarray(start, start + compSize);
      if (method === 0) out.set(name, Buffer.from(data));
      else if (method === 8) out.set(name, inflateRawSync(data));
      else throw new Error(`対応していない圧縮方式です: ${name}`);
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  for (const name of names) if (!out.has(name)) throw new Error(`ZIP に ${name} がありません`);
  return out;
}

async function webview2Sdk() {
  mkdirSync(CACHE, { recursive: true });
  const { version, sha256: expected } = WEBVIEW2_SDK;
  const pkgPath = join(CACHE, `microsoft.web.webview2.${version}.nupkg`);
  let pkg = existsSync(pkgPath) ? readFileSync(pkgPath) : undefined;
  if (!pkg || sha256(pkg) !== expected) {
    log(`WebView2 SDK ${version} を nuget.org から取得しています…`);
    pkg = await download(`https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/${version}/microsoft.web.webview2.${version}.nupkg`);
    writeFileSync(pkgPath, pkg);
  }
  const actual = sha256(pkg);
  if (actual !== expected) throw new Error(`WebView2 SDK の SHA256 が一致しません（期待: ${expected} / 実際: ${actual}）`);
  log(`    WebView2 SDK ${version} の SHA256 を照合しました`);
  const files = readZipEntries(pkg, ['build/native/include/WebView2.h', 'build/native/x64/WebView2Loader.dll', 'LICENSE.txt']);
  const sdk = join(BUILD, 'webview2-sdk');
  mkdirSync(join(sdk, 'include'), { recursive: true });
  writeFileSync(join(sdk, 'include', 'WebView2.h'), files.get('build/native/include/WebView2.h'));
  return { include: join(sdk, 'include'), loaderDll: files.get('build/native/x64/WebView2Loader.dll'), license: files.get('LICENSE.txt') };
}

/**
 * MinGW-w64 のコマンドを探す。Linux の配布は x86_64-w64-mingw32-○○ という名前だけを入れるが、
 * Windows の配布（WinLibs など）は windres に接頭辞が付かないことがあるため、Windows では接頭辞なしの名前も探す
 */
/** ビルドしたソースのコミット（GitHub Actions では GITHUB_SHA。手元では git から読む。分からなければ unknown） */
function sourceCommit() {
  if (/^[0-9a-f]{40}$/.test(process.env.GITHUB_SHA ?? '')) return process.env.GITHUB_SHA;
  try {
    const sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim();
    const dirty = execFileSync('git', ['status', '--porcelain', '--', '.'], { cwd: ROOT, encoding: 'utf8' }).trim() !== '';
    return dirty ? `${sha}（手元の変更あり）` : sha;
  } catch {
    return 'unknown';
  }
}

/** どのソース・どの環境で作ったかの記録（Release に添付する） */
function buildInfo({ outName, outSha, commit, nodeSha, toolchain }) {
  const env = process.env;
  const inActions = env.GITHUB_ACTIONS === 'true';
  return [
    `公開前チェック（koukai-check）${pkg.version} Windows 版のビルド情報`,
    '',
    `ファイル: ${outName}`,
    `SHA256: ${outSha}`,
    `ソースのコミット: ${commit}`,
    `ビルドした場所: ${inActions ? `GitHub Actions（${env.GITHUB_REPOSITORY}・${env.GITHUB_REF}）` : '手元の PC（GitHub Actions ではない）'}`,
    ...(inActions ? [`ワークフローの実行: ${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}（試行 ${env.GITHUB_RUN_ATTEMPT}）`, `ランナー: ${env.ImageOS ?? ''} ${env.ImageVersion ?? ''}`.trim()] : []),
    `Node.js: ${NODE_VERSION}（公式 node.exe の SHA256: ${nodeSha}）`,
    `C++ コンパイラ: ${toolchain.cxx}`,
    `windres: ${toolchain.windres}`,
    `WebView2 SDK: ${WEBVIEW2_SDK.version}`,
    '',
  ].join('\n');
}

function findTool(tool) {
  const names = process.platform === 'win32' ? [`x86_64-w64-mingw32-${tool}`, tool] : [`x86_64-w64-mingw32-${tool}`];
  for (const name of names) {
    const r = spawnSync(name, ['--version'], { stdio: 'ignore' });
    if (!r.error && r.status === 0) return name;
  }
  throw new Error(
    `${names[0]} が見つかりません。MinGW-w64 を入れてください` +
      '（Ubuntu: sudo apt install g++-mingw-w64-x86-64-win32 binutils-mingw-w64-x86-64／Windows: winget install BrechtSanders.WinLibs.POSIX.UCRT）',
  );
}

async function buildWindowHost() {
  const cxx = findTool('g++');
  const windres = findTool('windres');
  const sdk = await webview2Sdk();
  mkdirSync(HOST_OUT, { recursive: true });
  const res = join(HOST_OUT, 'app.res.o');
  execFileSync(windres, ['-c', '65001', 'app.rc', '-O', 'coff', '-o', res], { cwd: HOST_SRC, stdio: 'inherit' });
  const exe = join(HOST_OUT, 'koukai-check-window.exe');
  execFileSync(
    cxx,
    [
      '-std=c++17', '-O2', '-Wall', '-Wno-unknown-pragmas', '-municode', '-mwindows', '-static', '-s',
      // 生成物にビルド環境のパスを残さない
      `-ffile-prefix-map=${ROOT}=.`, `-ffile-prefix-map=${BUILD}=.`,
      '-I', join(HOST_SRC, 'include-shim'), '-I', sdk.include,
      join(HOST_SRC, 'host.cpp'), res, '-o', exe,
      '-lole32', '-lshell32', '-luser32', '-lgdi32', '-luuid',
    ],
    { stdio: 'inherit' },
  );
  // マニフェストを app.manifest の1つだけにする（MinGW-w64 が自動でリンクする既定のマニフェストを取り除く）
  const manifest = readFileSync(join(HOST_SRC, 'app.manifest'));
  const withManifest = await setManifest(readFileSync(exe), manifest);
  const found = await manifestsOf(withManifest);
  if (found.length !== 1 || !found[0].equals(manifest)) throw new Error(`専用ウィンドウのマニフェストが ${found.length} 個です（app.manifest の1つだけのはず）`);
  writeFileSync(exe, withManifest);
  log('    マニフェスト: app.manifest の1つだけ（既定のマニフェストを取り除きました）');
  const dll = join(HOST_OUT, 'WebView2Loader.dll');
  writeFileSync(dll, sdk.loaderDll);
  writeFileSync(join(HOST_OUT, 'WebView2-LICENSE.txt'), sdk.license);
  const exeBuf = readFileSync(exe);
  if (peSubsystem(exeBuf) !== 2) throw new Error('専用ウィンドウが「ウィンドウのアプリ」になっていません');
  const versionOf = (tool) => execFileSync(tool, ['--version'], { encoding: 'utf8' }).split(/\r?\n/)[0]?.trim() ?? '';
  // mingw-w64 のランタイムの版（ヘッダーのマクロをコンパイラに展開させる）
  const mingw = execFileSync(cxx, ['-E', '-P', '-x', 'c++', '-'], { input: '#include <_mingw.h>\n__MINGW64_VERSION_STR\n', encoding: 'utf8' })
    .trim()
    .split(/\r?\n/)
    .pop()
    ?.replace(/["\s]/g, ''); // 「14 . 0 . 0」のように空白で区切って出ることがある
  const gcc = execFileSync(cxx, ['-dumpfullversion'], { encoding: 'utf8' }).trim();
  return { exe, dll, license: sdk.license, exeSize: exeBuf.length, toolchain: { cxx: versionOf(cxx), windres: versionOf(windres), gcc, mingw } };
}

// ───────────── 7. アイコン・バージョン情報、「ウィンドウのアプリ」への切り替え ─────────────

/**
 * exe のアイコンとバージョン情報（エクスプローラーのプロパティ・タスクマネージャーに出る名前）を差し替える。
 * 差し替えないと、Node.js のアイコンと「Node.js JavaScript Runtime」が表示され、初めての人には何のアプリか分からない。
 */
export async function setAppResources(buf, icoBuf) {
  const ResEdit = await import('resedit');
  const exe = ResEdit.NtExecutable.from(buf, { ignoreCert: true });
  const res = ResEdit.NtExecutableResource.from(exe);
  const icon = ResEdit.Data.IconFile.from(icoBuf);
  const groups = ResEdit.Resource.IconGroupEntry.fromEntries(res.entries);
  if (groups.length === 0) throw new Error('アイコンが見つかりません');
  for (const g of groups) {
    ResEdit.Resource.IconGroupEntry.replaceIconsForResource(res.entries, g.id, g.lang, icon.icons.map((i) => i.data));
  }
  const [vi] = ResEdit.Resource.VersionInfo.fromEntries(res.entries);
  if (!vi) throw new Error('バージョン情報が見つかりません');
  const [major, minor, patch] = pkg.version.split('.').map(Number);
  for (const lang of vi.getAllLanguagesForStringValues()) {
    vi.setFileVersion(major, minor, patch, 0, lang.lang);
    vi.setProductVersion(major, minor, patch, 0, lang.lang);
    vi.setStringValues(lang, {
      CompanyName: 'nionxx-lab',
      ProductName: '公開前チェック',
      FileDescription: '公開前チェック',
      FileVersion: pkg.version,
      ProductVersion: pkg.version,
      OriginalFilename: 'koukai-check.exe',
      InternalName: 'koukai-check',
      LegalCopyright: 'Copyright (c) 2026 nionxx-lab. PolyForm Shield License 1.0.0. Includes third-party software (see THIRD-PARTY-NOTICES.txt).',
    });
  }
  vi.outputToResourceEntries(res.entries);
  // allowShrink：書き直したリソースが元より小さいとき、セクションの大きさ（ファイル上・メモリ上）も合わせて縮める。
  // 縮めないと、ファイル上の大きさ（SizeOfRawData）だけが元のまま残り、次のセクション（.reloc）と重なって見える。
  // Windows のローダーはメモリ上の大きさで読むので動くが、postject（LIEF）が再配置情報を誤って読み
  // 「Relocation corrupted: BlockSize is out of bound」と警告していた
  res.outputResource(exe, false, true);
  return Buffer.from(exe.generate());
}

/** RT_MANIFEST（種類 24）を、渡したマニフェストの1つだけにする */
export async function setManifest(buf, manifest) {
  const ResEdit = await import('resedit');
  const exe = ResEdit.NtExecutable.from(buf, { ignoreCert: true });
  const res = ResEdit.NtExecutableResource.from(exe);
  res.entries = res.entries.filter((e) => e.type !== 24);
  // id 1 = CREATEPROCESS_MANIFEST_RESOURCE_ID。言語は windres の既定と同じ英語（米国）
  res.entries.push({ type: 24, id: 1, lang: 0x409, codepage: 0, bin: manifest.buffer.slice(manifest.byteOffset, manifest.byteOffset + manifest.byteLength) });
  res.outputResource(exe, false, true);
  return Buffer.from(exe.generate());
}

/** exe に入っているマニフェストの中身 */
export async function manifestsOf(buf) {
  const ResEdit = await import('resedit');
  const exe = ResEdit.NtExecutable.from(buf, { ignoreCert: true });
  return ResEdit.NtExecutableResource.from(exe)
    .entries.filter((e) => e.type === 24)
    .map((e) => Buffer.from(e.bin));
}

/**
 * PE の構造の検査（生成物の確認用）。
 * ・セクションのファイル上の範囲が重ならない
 * ・再配置情報（.reloc）を最後まで読め、どのブロック・項目も exe の範囲に収まる
 * 問題がなければ再配置情報のブロック数と項目数を返す。問題があれば例外にする
 */
export function checkPeLayout(buf) {
  const opt = optionalHeader(buf);
  const pe = opt - 24;
  const count = buf.readUInt16LE(pe + 6);
  const optSize = buf.readUInt16LE(pe + 20);
  const sizeOfImage = buf.readUInt32LE(opt + 56);
  const sections = [];
  for (let i = 0; i < count; i++) {
    const o = opt + optSize + i * 40;
    sections.push({ name: buf.toString('latin1', o, o + 8).replace(/ +$/, ''), va: buf.readUInt32LE(o + 12), vsize: buf.readUInt32LE(o + 8), raw: buf.readUInt32LE(o + 20), rawSize: buf.readUInt32LE(o + 16) });
  }
  const byRaw = sections.filter((s) => s.rawSize > 0).sort((a, b) => a.raw - b.raw);
  for (let i = 1; i < byRaw.length; i++) {
    const prev = byRaw[i - 1];
    if (prev.raw + prev.rawSize > byRaw[i].raw) throw new Error(`セクション ${prev.name} と ${byRaw[i].name} のファイル上の範囲が重なっています`);
  }
  const relocRva = buf.readUInt32LE(opt + 112 + 5 * 8);
  const relocSize = buf.readUInt32LE(opt + 112 + 5 * 8 + 4);
  if (relocSize === 0) return { blocks: 0, entries: 0 };
  const sec = sections.find((s) => relocRva >= s.va && relocRva + relocSize <= s.va + Math.max(s.vsize, 1));
  if (!sec) throw new Error('再配置情報がどのセクションにも収まっていません');
  let off = relocRva - sec.va + sec.raw;
  const end = off + relocSize;
  let blocks = 0;
  let entries = 0;
  while (off < end) {
    const va = buf.readUInt32LE(off);
    const size = buf.readUInt32LE(off + 4);
    if (size < 8 || off + size > end || va >= sizeOfImage) throw new Error(`再配置情報のブロック ${blocks} が壊れています`);
    for (let p = off + 8; p < off + size; p += 2) {
      const e = buf.readUInt16LE(p);
      if (e >> 12 === 0) continue;
      if (va + (e & 0xfff) + 8 > sizeOfImage) throw new Error(`再配置情報の項目が exe の範囲外を指しています（ブロック ${blocks}）`);
      entries++;
    }
    off += size;
    blocks++;
  }
  return { blocks, entries };
}

function optionalHeader(buf) {
  const pe = buf.readUInt32LE(0x3c);
  if (buf.toString('latin1', pe, pe + 4) !== 'PE\0\0') throw new Error('PE ファイルではありません');
  return pe + 24;
}

export function peSubsystem(buf) {
  return buf.readUInt16LE(optionalHeader(buf) + 68);
}

/**
 * PE の Subsystem を書き換える（3 = コンソール → 2 = ウィンドウのアプリ）。
 * 2 にすると、ダブルクリックしても黒い画面（コンソール）が開かない。Node.js は標準出力がない場合も動く。
 */
export function setPeSubsystem(buf, subsystem) {
  const out = Buffer.from(buf);
  out.writeUInt16LE(subsystem, optionalHeader(out) + 68);
  return out;
}

// ───────────── 5. 公式の node.exe を取得して照合 ─────────────

async function download(url) {
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok) throw new Error(`ダウンロードに失敗しました: ${url} (HTTP ${res.status})`);
  return Buffer.from(await res.arrayBuffer());
}

async function officialNodeExe() {
  mkdirSync(CACHE, { recursive: true });
  const exePath = join(CACHE, `node-${NODE_VERSION}-win-x64.exe`);
  const sums = (await download(`https://nodejs.org/dist/${NODE_VERSION}/SHASUMS256.txt`)).toString('utf8');
  const expected = sums.split('\n').find((l) => l.endsWith('  win-x64/node.exe'))?.split(/\s+/)[0];
  if (!expected) throw new Error('SHASUMS256.txt に win-x64/node.exe がありません');

  let exe = existsSync(exePath) ? readFileSync(exePath) : undefined;
  if (!exe || sha256(exe) !== expected) {
    log(`node.exe ${NODE_VERSION} を nodejs.org から取得しています…`);
    exe = await download(`https://nodejs.org/dist/${NODE_VERSION}/win-x64/node.exe`);
    writeFileSync(exePath, exe);
  }
  const actual = sha256(exe);
  if (actual !== expected) throw new Error(`node.exe の SHA256 が公式の値と一致しません（期待: ${expected} / 実際: ${actual}）`);
  log(`node.exe の SHA256 を公式の SHASUMS256.txt と照合しました: ${actual}`);
  return { exe, sha256: actual };
}

function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

// ───────────── 6. Authenticode 署名を外す ─────────────

/**
 * PE ファイルの「証明書テーブル」（データディレクトリの4番）を取り除く。
 * Windows の `signtool remove /s` と同じ処理。署名を残したまま中身を書き換えると「壊れた署名」になるため。
 */
export function stripAuthenticode(buf) {
  const opt = optionalHeader(buf);
  const magic = buf.readUInt16LE(opt);
  const dirBase = opt + (magic === 0x20b ? 112 : 96); // PE32+ / PE32
  const secEntry = dirBase + 4 * 8;
  const certOffset = buf.readUInt32LE(secEntry);
  const certSize = buf.readUInt32LE(secEntry + 4);
  if (certOffset === 0 || certSize === 0) return { buf, removed: false };
  if (certOffset + certSize !== buf.length) throw new Error('証明書テーブルがファイル末尾にありません');
  const out = Buffer.from(buf.subarray(0, certOffset));
  out.writeUInt32LE(0, secEntry);
  out.writeUInt32LE(0, secEntry + 4);
  out.writeUInt32LE(0, opt + 64); // CheckSum（.exe では検証されない。古い値を残さない）
  return { buf: out, removed: true };
}

// ───────────── 実行 ─────────────

async function main() {
  if (!/^v\d+\.\d+\.\d+$/.test(NODE_VERSION) || Number(NODE_VERSION.slice(1).split('.')[0]) < 22) {
    throw new Error(`Node.js 22 以上でビルドしてください（現在: ${NODE_VERSION}）`);
  }
  const { inject } = await import('postject');

  log('1/7 TypeScript を CommonJS で出力');
  compileCjs();

  log('2/7 1ファイルに結合');
  const { code, moduleCount } = bundleCjs(CJS, 'cli/index.js');
  const bundlePath = join(BUILD, 'koukai-check.cjs');
  writeFileSync(bundlePath, code);
  log(`    ${moduleCount} モジュール / ${(code.length / 1024).toFixed(0)} KB`);

  log('3/7 専用ウィンドウ（WebView2）をビルド');
  const host = await buildWindowHost();
  log(`    koukai-check-window.exe ${(host.exeSize / 1024).toFixed(0)} KB / WebView2Loader.dll ${(statSync(host.dll).size / 1024).toFixed(0)} KB`);

  log('4/7 SEA 用のデータを作成');
  const blobPath = join(BUILD, 'sea-prep.blob');
  const configPath = join(BUILD, 'sea-config.json');
  // main / output / assets は相対パスで書き、build/sea で実行する（blob に開発環境の絶対パスを残さないため）
  writeFileSync(
    configPath,
    JSON.stringify(
      {
        main: 'koukai-check.cjs',
        output: 'sea-prep.blob',
        disableExperimentalSEAWarning: true,
        useSnapshot: false,
        useCodeCache: false,
        assets: {
          'windows-host/koukai-check-window.exe': 'windows-host/koukai-check-window.exe',
          'windows-host/WebView2Loader.dll': 'windows-host/WebView2Loader.dll',
        },
      },
      null,
      2,
    ),
  );
  execFileSync(process.execPath, ['--experimental-sea-config', 'sea-config.json'], { stdio: 'inherit', cwd: BUILD });
  const blob = readFileSync(blobPath);

  log('5/7 公式の node.exe を取得・照合');
  const { exe, sha256: nodeSha } = await officialNodeExe();

  log('6/7 署名を外す');
  const stripped = stripAuthenticode(exe);
  log(`    署名: ${stripped.removed ? '外しました' : 'もともとありません'}`);

  log('7/7 埋め込み・ウィンドウのアプリに切り替え');
  mkdirSync(RELEASE, { recursive: true });
  const outName = `${pkg.name}-${pkg.version}-win-x64.exe`;
  const outPath = join(RELEASE, outName);
  writeFileSync(outPath, await setAppResources(stripped.buf, readFileSync(join(HOST_SRC, 'icon.ico'))));
  await inject(outPath, 'NODE_SEA_BLOB', blob, { sentinelFuse: SENTINEL_FUSE });
  writeFileSync(outPath, setPeSubsystem(readFileSync(outPath), 2));
  const outBuf = readFileSync(outPath);
  if (peSubsystem(outBuf) !== 2) throw new Error('ウィンドウのアプリに切り替えられませんでした');
  const layout = checkPeLayout(outBuf);
  log(`    PE の構造: セクションの重なりなし・再配置情報 ${layout.blocks} ブロック / ${layout.entries} 項目をすべて確認`);
  if (outBuf.includes(Buffer.from(ROOT))) throw new Error('生成物にビルド環境のパスが含まれています');
  const outSha = sha256(outBuf);
  writeFileSync(join(RELEASE, 'THIRD-PARTY-NOTICES.txt'), thirdPartyNotices({ nodeVersion: NODE_VERSION, webview2License: host.license, toolchain: host.toolchain }));
  const commit = sourceCommit();
  writeFileSync(join(RELEASE, 'BUILD-INFO.txt'), buildInfo({ outName, outSha, commit, nodeSha, toolchain: host.toolchain }));
  // 配布する（Release に添付する）ファイルすべての SHA256。1行目は exe（sha256sum -c・Get-FileHash で確かめられる形）
  const assets = [outName, 'THIRD-PARTY-NOTICES.txt', 'BUILD-INFO.txt', 'README-ja.txt'];
  writeFileSync(
    join(RELEASE, 'SHA256SUMS.txt'),
    [
      ...assets.map((name) => `${sha256(readFileSync(join(RELEASE, name)))}  ${name}`),
      '',
      `# ソースのコミット: ${commit}`,
      `# 元にした公式 node.exe（${NODE_VERSION} win-x64）: ${nodeSha}`,
      `# 埋め込んだ専用ウィンドウ koukai-check-window.exe: ${sha256(readFileSync(host.exe))}`,
      `# 埋め込んだ WebView2Loader.dll（WebView2 SDK ${WEBVIEW2_SDK.version}）: ${sha256(readFileSync(host.dll))}`,
      '',
    ].join('\n'),
  );
  log(`    ${relative(ROOT, outPath)} (${(statSync(outPath).size / 1024 / 1024).toFixed(1)} MB)`);
  log(`    SHA256: ${outSha}`);

  // 動作確認用の Linux 版（同じ blob。Windows 版と同じ SEA の仕組みで起動する）
  if (process.platform === 'linux') {
    const linuxPath = join(BUILD, 'koukai-check-linux-x64');
    copyFileSync(process.execPath, linuxPath);
    chmodSync(linuxPath, 0o755);
    await inject(linuxPath, 'NODE_SEA_BLOB', blob, { sentinelFuse: SENTINEL_FUSE });
    log(`    動作確認用: ${relative(ROOT, linuxPath)}`);
  }
}

/**
 * exe に含める第三者のソフトウェアのライセンス文書（third_party/licenses。各プロジェクトの、使っている版のタグから取得したもの）。
 * 版と SHA256 を固定し、ビルドに使った版と違えば止める（告知と中身がずれた配布物を作らないため）
 */
export const THIRD_PARTY_LICENSES = {
  node: { version: 'v24.18.0', file: 'node-v24.18.0-LICENSE.txt', sha256: '148eacf7863ef4329224a29398623077200a27194aa075569faf4a0a85566ca5' },
  mingwRuntime: { version: '14.0.0', file: 'mingw-w64-v14.0.0-runtime-COPYING.txt', sha256: '1db8da07b436c68833c0673ffee3d9fcb2526047f3820b81661865dfedc79a1f' },
  winpthreads: { version: '14.0.0', file: 'mingw-w64-v14.0.0-winpthreads-COPYING.txt', sha256: '63263614cdd29f2f93cba85e992f041b31f9fc7b4033692f31269489a8a1b177' },
  gccRuntime: { version: '16.2.0', file: 'gcc-16.2.0-COPYING.RUNTIME.txt', sha256: '9d6b43ce4d8de0c878bf16b54d8e7a10d9bd42b75178153e3af6a815bdc90f74' },
};

/** ライセンス文書を読み、SHA256 を確かめる */
export function readThirdPartyLicense(entry) {
  const buf = readFileSync(join(ROOT, 'third_party', 'licenses', entry.file));
  const actual = sha256(buf);
  if (actual !== entry.sha256) throw new Error(`${entry.file} の SHA256 が一致しません（期待: ${entry.sha256} / 実際: ${actual}）`);
  return buf.toString('utf8').replace(/\r\n/g, '\n').trim();
}

const RULE = '================================================================================';

/** THIRD-PARTY-NOTICES.txt の中身 */
export function thirdPartyNotices({ nodeVersion, webview2License, toolchain }) {
  const L = THIRD_PARTY_LICENSES;
  if (nodeVersion !== L.node.version) {
    throw new Error(`exe に含める Node.js ${nodeVersion} のライセンス文書がありません（third_party/licenses には ${L.node.version} だけ）。Node.js ${L.node.version} でビルドするか、文書を追加してください`);
  }
  if (toolchain && (!toolchain.gcc.includes(L.gccRuntime.version) || toolchain.mingw !== L.mingwRuntime.version)) {
    throw new Error(`MinGW-w64 の版（GCC: ${toolchain.gcc} / mingw-w64: ${toolchain.mingw}）が、ライセンス文書の版（GCC ${L.gccRuntime.version} / mingw-w64 ${L.mingwRuntime.version}）と違います`);
  }
  const section = (title, lines, text) => [RULE, title, ...lines, RULE, '', text, '', ''];
  return [
    '公開前チェック（koukai-check）Windows 版に含まれる第三者のソフトウェア',
    'Third-party software included in the koukai-check Windows executable',
    '',
    'koukai-check 本体は PolyForm Shield License 1.0.0 で提供しています（LICENSE を参照）。',
    '次の第三者のソフトウェアは、それぞれのライセンスに従います（本体のライセンスは適用されません）。',
    'The components below are licensed under their own terms, not under the koukai-check license.',
    '',
    ...section(
      `1. Node.js ${L.node.version}（実行環境として exe に含まれる / runtime embedded in the executable）`,
      ['https://nodejs.org/', `https://github.com/nodejs/node/blob/${L.node.version}/LICENSE`, 'Node.js 本体は MIT License。同梱している依存ライブラリのライセンスも、以下の全文に含まれる。'],
      readThirdPartyLicense(L.node),
    ),
    ...section(
      `2. Microsoft Edge WebView2 SDK ${WEBVIEW2_SDK.version}（WebView2Loader.dll・WebView2.h / BSD-3-Clause）`,
      ['https://www.nuget.org/packages/Microsoft.Web.WebView2'],
      webview2License.toString('utf8').replace(/\r\n/g, '\n').trim(),
    ),
    ...section(
      `3. MinGW-w64 runtime ${L.mingwRuntime.version}（専用ウィンドウ koukai-check-window.exe に静的にリンク / statically linked into koukai-check-window.exe）`,
      ['https://www.mingw-w64.org/', 'COPYING.MinGW-w64-runtime.txt'],
      readThirdPartyLicense(L.mingwRuntime),
    ),
    ...section(
      `4. MinGW-w64 winpthreads ${L.winpthreads.version}（専用ウィンドウに静的にリンク / statically linked）`,
      ['mingw-w64-libraries/winpthreads/COPYING'],
      readThirdPartyLicense(L.winpthreads),
    ),
    ...section(
      `5. GCC ${L.gccRuntime.version} runtime libraries（libgcc・libstdc++。専用ウィンドウに静的にリンク / statically linked）`,
      [
        'GNU General Public License version 3 with the GCC Runtime Library Exception, version 3.1.',
        'GPL version 3: https://www.gnu.org/licenses/gpl-3.0.html',
        'The GCC Runtime Library Exception (below) permits distributing the combined work under terms of our choice.',
      ],
      readThirdPartyLicense(L.gccRuntime),
    ),
  ].join('\n');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`[build:win] 失敗しました: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  });
}
