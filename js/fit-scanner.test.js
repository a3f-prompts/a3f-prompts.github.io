/**
 * Tests for FIT scanner (disk image FIT extraction).
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');

const { FDT, buildTestFit } = require('./test-helpers');

// Load FitScanner
const { readFileSync } = require('fs');
const { join } = require('path');
const scannerCode = readFileSync(join(__dirname, 'fit-scanner.js'), 'utf8');
const FitScanner = new Function(scannerCode.replace('const FitScanner =', 'return'))();

describe('FitScanner', () => {
  let fitBinary;

  before(async () => {
    const result = await buildTestFit();
    fitBinary = result.binary;
  });

  it('finds a FIT image at the start of a buffer', () => {
    const results = FitScanner.scan(fitBinary);
    assert.equal(results.length, 1);
    assert.equal(results[0].offset, 0);
  });

  it('finds a FIT image embedded after padding', () => {
    // Simulate a disk image: 4KB of zeros, then the FIT
    const padding = new Uint8Array(4096);
    const disk = new Uint8Array(padding.length + fitBinary.length);
    disk.set(padding, 0);
    disk.set(fitBinary, padding.length);

    const results = FitScanner.scan(disk);
    assert.equal(results.length, 1);
    assert.equal(results[0].offset, 4096);
  });

  it('finds multiple FIT images in a disk image', async () => {
    const fit1 = (await buildTestFit(new TextEncoder().encode('kernel1'))).binary;
    const fit2 = (await buildTestFit(new TextEncoder().encode('kernel2'))).binary;

    const gap = new Uint8Array(512);
    const disk = new Uint8Array(fit1.length + gap.length + fit2.length);
    disk.set(fit1, 0);
    disk.set(gap, fit1.length);
    disk.set(fit2, fit1.length + gap.length);

    const results = FitScanner.scan(disk);
    assert.equal(results.length, 2);
    assert.equal(results[0].offset, 0);
    assert.equal(results[1].offset, fit1.length + gap.length);
  });

  it('ignores plain DTBs without /configurations', () => {
    // A minimal DTB without configurations node
    const tree = {
      header: { version: 17, last_comp_version: 16, boot_cpuid_phys: 0 },
      reserveEntries: [],
      root: {
        name: '',
        properties: [{ name: 'model', data: new TextEncoder().encode('board\0') }],
        children: [],
      },
    };
    const dtb = FDT.serialize(tree);
    const results = FitScanner.scan(dtb);
    assert.equal(results.length, 0);
  });

  it('extract returns correct slice', () => {
    const padding = new Uint8Array(1024);
    const disk = new Uint8Array(padding.length + fitBinary.length + 512);
    disk.set(fitBinary, padding.length);

    const extracted = FitScanner.extract(disk, 1024, fitBinary.length);
    assert.equal(extracted.length, fitBinary.length);

    // Should parse as valid FIT
    const tree = FDT.parse(extracted);
    assert.ok(FDT.findNode(tree.root, ['images']));
  });

  it('splice replaces FIT in disk image (same size)', () => {
    const padding = new Uint8Array(1024);
    padding.fill(0xAA);
    const trailer = new Uint8Array(512);
    trailer.fill(0xBB);
    const disk = new Uint8Array(padding.length + fitBinary.length + trailer.length);
    disk.set(padding, 0);
    disk.set(fitBinary, padding.length);
    disk.set(trailer, padding.length + fitBinary.length);

    // Create a "modified" FIT of the same size
    const modified = new Uint8Array(fitBinary.length);
    modified.fill(0xCC);

    const result = FitScanner.splice(disk, 1024, fitBinary.length, modified);
    assert.equal(result.length, disk.length);
    // Padding preserved
    assert.equal(result[0], 0xAA);
    // Modified data in place
    assert.equal(result[1024], 0xCC);
    // Trailer preserved
    assert.equal(result[1024 + fitBinary.length], 0xBB);
  });

  it('splice handles different size FIT', () => {
    const padding = new Uint8Array(512);
    const disk = new Uint8Array(padding.length + fitBinary.length + 256);
    disk.set(fitBinary, padding.length);
    disk.fill(0xFF, padding.length + fitBinary.length);

    const smaller = new Uint8Array(100);
    smaller.fill(0xDD);

    const result = FitScanner.splice(disk, 512, fitBinary.length, smaller);
    assert.equal(result.length, disk.length - fitBinary.length + 100);
    assert.equal(result[512], 0xDD);
    assert.equal(result[612], 0xFF); // trailer shifted
  });
});
