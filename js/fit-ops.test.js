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
  FDT, FitOps, buildTestFit, buildMinimalDtb, buildExternalDataFit,
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
    assert.equal(model, 'Test Board [rooted by ifitfitsisits.com]');
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
      assert.ok(model.includes('[rooted by ifitfitsisits.com]'),
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
    assert.equal(newModel, 'Test Board [rooted by ifitfitsisits.com]', 'Modified /model should append rooting tag');
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
      assert.ok(model.includes('[rooted by ifitfitsisits.com]'),
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
