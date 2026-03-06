/**
 * Integration tests: verify bypassed FIT images pass fit_check_sign.
 *
 * Tests every operation the website supports (changeDtModel, replaceKernel,
 * appendInitramfs) and all valid combinations, against real signed FIT images.
 *
 * Requires fit_check_sign binary and test fixtures from ../dtc/fit-demo/.
 * Tests are skipped if those are not available.
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('child_process');
const { readFileSync, writeFileSync, existsSync } = require('fs');
const path = require('path');
const { webcrypto } = require('crypto');

const {
  FDT, FitOps,
} = require('./test-helpers');

const FIT_CHECK_SIGN = path.resolve(__dirname, '..', '..', 'dtc', 'fit-demo', 'fit_check_sign');
const KEY_DTB = path.resolve(__dirname, '..', '..', 'dtc', 'fit-demo', 'keys', 'dev.dtb');

// Large real-world FIT (116 configs, gzip kernel, uncompressed ramdisk)
// DT data is anonymized (zeros) — changeDtModel will fail
const ANON_FIT = path.resolve(__dirname, '..', '..', 'dtc', 'fit-demo', 'anon.fit');
const ANON_CONFIG = 'n85xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';

// Smaller anonymized FIT (2 configs, uncompressed kernel, gzip ramdisk)
// DT data is anonymized; ramdisk is anonymized gzip (can't decompress)
const ANON2_FIT = path.resolve(__dirname, '..', '..', 'dtc', 'fit-demo', 'anon2.fit');
const ANON2_CONFIG = 'n04xxxxxxxxx';
const ANON2_CONFIG2 = 'n05xxxxxxxxx';

// Simple ITS-based FIT (re-signed at test time, real data throughout)
const IMAGE_ITS = path.resolve(__dirname, '..', '..', 'dtc', 'fit-demo', 'image.its');
const IMAGE_FIT_DIR = path.resolve(__dirname, '..', '..', 'dtc', 'fit-demo');
const IMAGE_CONFIG_A = 'conf-board-a';
const IMAGE_CONFIG_B = 'conf-board-b';

const MKIMAGE = path.resolve(__dirname, '..', '..', 'u-boot', 'tools', 'mkimage');

const canRunAnon = existsSync(FIT_CHECK_SIGN) && existsSync(ANON_FIT) && existsSync(KEY_DTB);
const canRunAnon2 = existsSync(FIT_CHECK_SIGN) && existsSync(ANON2_FIT) && existsSync(KEY_DTB);
const canRunImage = existsSync(FIT_CHECK_SIGN) && existsSync(IMAGE_ITS) && existsSync(KEY_DTB) && existsSync(MKIMAGE);

let tmpCounter = 0;
function tmpFit(label) {
  return `/tmp/fit-integ-${label}-${++tmpCounter}.fit`;
}

function fitCheckSign(fitPath, keyDtb, config) {
  try {
    const out = execFileSync(FIT_CHECK_SIGN, ['-f', fitPath, '-k', keyDtb, '-c', config], {
      timeout: 30000,
    });
    return { ok: true, output: out.toString() };
  } catch (e) {
    return { ok: false, output: (e.stdout || '').toString() + (e.stderr || '').toString() };
  }
}

async function bypassAndVerify(fitBuffer, opts, keyDtb, config, label) {
  const output = await FitOps.root(fitBuffer, opts);
  const p = tmpFit(label);
  writeFileSync(p, output);
  const result = fitCheckSign(p, keyDtb, config);
  assert.ok(result.ok, `${label} should pass fit_check_sign:\n${result.output}`);
  return output;
}

// ---------------------------------------------------------------------------
// anon.fit — large real-world image (116 configs, gzip kernel, no-compress ramdisk)
// DT data is anonymized → changeDtModel cannot be tested here
// ---------------------------------------------------------------------------
describe('anon.fit: real-world FIT with 116 configs', { skip: !canRunAnon && 'anon.fit or tools not found' }, () => {
  let fitBuffer;

  before(() => {
    fitBuffer = new Uint8Array(readFileSync(ANON_FIT));
  });

  it('original passes verification', () => {
    const result = fitCheckSign(ANON_FIT, KEY_DTB, ANON_CONFIG);
    assert.ok(result.ok, `Original should pass: ${result.output}`);
  });

  it('kernel-only bypass', async () => {
    await bypassAndVerify(fitBuffer, {
      changeDtModel: false,
      replaceKernel: true,
      kernelData: new Uint8Array(1024).fill(0x42),
    }, KEY_DTB, ANON_CONFIG, 'anon-kernel');
  });

  it('ramdisk-only bypass (uncompressed ramdisk)', async () => {
    await bypassAndVerify(fitBuffer, {
      changeDtModel: false,
      replaceKernel: false,
      appendInitramfs: true,
      initramfsData: new Uint8Array(256).fill(0xBB),
    }, KEY_DTB, ANON_CONFIG, 'anon-ramdisk');
  });

  it('kernel + ramdisk bypass', async () => {
    await bypassAndVerify(fitBuffer, {
      changeDtModel: false,
      replaceKernel: true,
      kernelData: new Uint8Array(2048).fill(0x55),
      appendInitramfs: true,
      initramfsData: new Uint8Array(512).fill(0xAA),
    }, KEY_DTB, ANON_CONFIG, 'anon-kernel-ramdisk');
  });
});

// ---------------------------------------------------------------------------
// anon2.fit — smaller anonymized FIT (2 configs)
// DT data anonymized → no changeDtModel
// ramdisk is gzip with anonymized data → no appendInitramfs
// ---------------------------------------------------------------------------
describe('anon2.fit: small FIT with 2 configs', { skip: !canRunAnon2 && 'anon2.fit or tools not found' }, () => {
  let fitBuffer;

  before(() => {
    fitBuffer = new Uint8Array(readFileSync(ANON2_FIT));
  });

  it('original passes verification (config 1)', () => {
    const result = fitCheckSign(ANON2_FIT, KEY_DTB, ANON2_CONFIG);
    assert.ok(result.ok, `Original config 1 should pass: ${result.output}`);
  });

  it('original passes verification (config 2)', () => {
    const result = fitCheckSign(ANON2_FIT, KEY_DTB, ANON2_CONFIG2);
    assert.ok(result.ok, `Original config 2 should pass: ${result.output}`);
  });

  it('kernel-only bypass (config 1)', async () => {
    await bypassAndVerify(fitBuffer, {
      changeDtModel: false,
      replaceKernel: true,
      kernelData: new Uint8Array(512).fill(0x33),
    }, KEY_DTB, ANON2_CONFIG, 'anon2-kernel-c1');
  });

  it('kernel-only bypass (config 2)', async () => {
    await bypassAndVerify(fitBuffer, {
      changeDtModel: false,
      replaceKernel: true,
      kernelData: new Uint8Array(512).fill(0x33),
    }, KEY_DTB, ANON2_CONFIG2, 'anon2-kernel-c2');
  });

  it('kernel bypass passes both configs simultaneously', async () => {
    const output = await FitOps.root(fitBuffer, {
      changeDtModel: false,
      replaceKernel: true,
      kernelData: new Uint8Array(256).fill(0x99),
    });
    const p = tmpFit('anon2-kernel-both');
    writeFileSync(p, output);

    const r1 = fitCheckSign(p, KEY_DTB, ANON2_CONFIG);
    assert.ok(r1.ok, `Config 1 should pass: ${r1.output}`);

    const r2 = fitCheckSign(p, KEY_DTB, ANON2_CONFIG2);
    assert.ok(r2.ok, `Config 2 should pass: ${r2.output}`);
  });
});

// ---------------------------------------------------------------------------
// image.fit — ITS-based FIT, re-signed at test time
// Has real data throughout: kernel (uncompressed), ramdisk (gzip), 2 FDTs
// All operations can be tested
// ---------------------------------------------------------------------------
describe('image.fit: freshly signed FIT with all real data', { skip: !canRunImage && 'image.its, mkimage, or tools not found' }, () => {
  let fitBuffer;
  const signedFit = '/tmp/fit-integ-image-signed.fit';

  before(() => {
    execFileSync(MKIMAGE, ['-f', IMAGE_ITS, '-k', path.dirname(KEY_DTB), '-K', KEY_DTB, '-r', signedFit], {
      cwd: IMAGE_FIT_DIR,
      timeout: 30000,
    });
    fitBuffer = new Uint8Array(readFileSync(signedFit));
  });

  it('freshly signed original passes (conf-board-a)', () => {
    const result = fitCheckSign(signedFit, KEY_DTB, IMAGE_CONFIG_A);
    assert.ok(result.ok, `Original board-a should pass: ${result.output}`);
  });

  it('freshly signed original passes (conf-board-b)', () => {
    const result = fitCheckSign(signedFit, KEY_DTB, IMAGE_CONFIG_B);
    assert.ok(result.ok, `Original board-b should pass: ${result.output}`);
  });

  // -- Single operations --

  it('DT model change only (conf-board-a)', async () => {
    await bypassAndVerify(fitBuffer, {
      changeDtModel: true,
      replaceKernel: false,
    }, KEY_DTB, IMAGE_CONFIG_A, 'image-dt-a');
  });

  it('DT model change only (conf-board-b)', async () => {
    await bypassAndVerify(fitBuffer, {
      changeDtModel: true,
      replaceKernel: false,
    }, KEY_DTB, IMAGE_CONFIG_B, 'image-dt-b');
  });

  it('kernel-only bypass (conf-board-a)', async () => {
    await bypassAndVerify(fitBuffer, {
      changeDtModel: false,
      replaceKernel: true,
      kernelData: new Uint8Array(8192).fill(0xDE),
    }, KEY_DTB, IMAGE_CONFIG_A, 'image-kernel-a');
  });

  it('ramdisk-only bypass with gzip decompression (conf-board-a)', async () => {
    await bypassAndVerify(fitBuffer, {
      changeDtModel: false,
      replaceKernel: false,
      appendInitramfs: true,
      initramfsData: new Uint8Array(1024).fill(0xEE),
    }, KEY_DTB, IMAGE_CONFIG_A, 'image-ramdisk-a');
  });

  // -- Pairwise combinations --

  it('DT model + kernel (conf-board-a)', async () => {
    await bypassAndVerify(fitBuffer, {
      changeDtModel: true,
      replaceKernel: true,
      kernelData: new Uint8Array(4096).fill(0xAB),
    }, KEY_DTB, IMAGE_CONFIG_A, 'image-dt-kernel-a');
  });

  it('DT model + ramdisk (conf-board-a)', async () => {
    await bypassAndVerify(fitBuffer, {
      changeDtModel: true,
      replaceKernel: false,
      appendInitramfs: true,
      initramfsData: new Uint8Array(2048).fill(0xCD),
    }, KEY_DTB, IMAGE_CONFIG_A, 'image-dt-ramdisk-a');
  });

  it('kernel + ramdisk (conf-board-a)', async () => {
    await bypassAndVerify(fitBuffer, {
      changeDtModel: false,
      replaceKernel: true,
      kernelData: new Uint8Array(4096).fill(0x11),
      appendInitramfs: true,
      initramfsData: new Uint8Array(512).fill(0x22),
    }, KEY_DTB, IMAGE_CONFIG_A, 'image-kernel-ramdisk-a');
  });

  // -- All three --

  it('all three: DT model + kernel + ramdisk (conf-board-a)', async () => {
    await bypassAndVerify(fitBuffer, {
      changeDtModel: true,
      replaceKernel: true,
      kernelData: new Uint8Array(8192).fill(0xFF),
      appendInitramfs: true,
      initramfsData: new Uint8Array(2048).fill(0xFE),
    }, KEY_DTB, IMAGE_CONFIG_A, 'image-all-three-a');
  });

  // -- Cross-config verification --

  it('all three bypass, both configs pass', async () => {
    const output = await FitOps.root(fitBuffer, {
      changeDtModel: true,
      replaceKernel: true,
      kernelData: new Uint8Array(4096).fill(0xA1),
      appendInitramfs: true,
      initramfsData: new Uint8Array(1024).fill(0xB2),
    });
    const p = tmpFit('image-all-both');
    writeFileSync(p, output);

    const resultA = fitCheckSign(p, KEY_DTB, IMAGE_CONFIG_A);
    assert.ok(resultA.ok, `conf-board-a should pass: ${resultA.output}`);

    const resultB = fitCheckSign(p, KEY_DTB, IMAGE_CONFIG_B);
    assert.ok(resultB.ok, `conf-board-b should pass: ${resultB.output}`);
  });

  // -- Structural verification --

  it('bypassed FIT has correct structural properties', async () => {
    const output = await FitOps.root(fitBuffer, {
      changeDtModel: true,
      replaceKernel: true,
      kernelData: new Uint8Array(256).fill(0x42),
      appendInitramfs: true,
      initramfsData: new Uint8Array(128).fill(0x43),
    });

    const tree = FDT.parse(output);
    const images = FDT.findNode(tree.root, ['images']);
    const names = images.children.map(c => c.name);

    // Modified nodes should have (Pwnd) in description
    const kernel = FDT.findNode(tree.root, ['images', 'kernel']);
    assert.ok(FDT.getStringProperty(kernel, 'description').includes('(Pwnd)'));

    // Compression should be 'none' on modified nodes
    assert.equal(FDT.getStringProperty(kernel, 'compression'), 'none');

    // Each bypassed image should have its own container
    for (const bypassed of ['kernel', 'ramdisk']) {
      const container = `orig-${bypassed}`;
      assert.ok(names.includes(container), `Expected ${container} in images children`);
      const origNode = images.children.find(c => c.name === container);
      assert.ok(origNode.children.some(c => c.name === bypassed),
        `Expected clone of ${bypassed} inside ${container}`);
      assert.ok(origNode.children.some(c => c.name === 'sentinel'),
        `Expected sentinel inside ${container}`);
    }

    // DT model change should also have its container for each board's fdt
    const fdtImages = images.children.filter(c => {
      const desc = FDT.getStringProperty(c, 'description') || '';
      return desc.includes('(Pwnd)') && FDT.getStringProperty(c, 'type') === 'flat_dt';
    });
    for (const fdtImg of fdtImages) {
      const container = `orig-${fdtImg.name}`;
      assert.ok(names.includes(container),
        `Expected ${container} for bypassed fdt image`);
    }

    // String block should be preserved
    const origDv = new DataView(fitBuffer.buffer, fitBuffer.byteOffset, fitBuffer.byteLength);
    const origStrOff = origDv.getUint32(12);
    const origStrSize = origDv.getUint32(32);
    const origStrings = fitBuffer.slice(origStrOff, origStrOff + origStrSize);

    const newDv = new DataView(output.buffer, output.byteOffset, output.byteLength);
    const newStrOff = newDv.getUint32(12);
    const newStrSize = newDv.getUint32(32);
    const newStrings = output.slice(newStrOff, newStrOff + newStrSize);

    assert.deepEqual(origStrings, newStrings, 'String block must be preserved');
  });
});
