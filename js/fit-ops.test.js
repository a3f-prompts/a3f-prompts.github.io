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

    // Must have an 'orig' node
    const origNode = outImages.children.find(c => c.name === 'orig');
    assert.ok(origNode, 'Expected /images/orig node');

    // orig must contain a clone of 'kernel'
    const origKernel = origNode.children.find(c => c.name === 'kernel');
    assert.ok(origKernel, 'Expected /images/orig/kernel node');

    // orig must contain sentinel
    const sentinel = origNode.children.find(c => c.name === 'sentinel');
    assert.ok(sentinel, 'Expected /images/orig/sentinel node');
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
    assert.ok(decoded.includes('/images/orig/kernel'), `hashed-nodes should reference /images/orig/kernel, got: ${decoded}`);
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
    assert.equal(model, 'rooted by ifitfitsisits.com');
  });

  it('DT model change creates orig node for fdt-1', async () => {
    const { binary } = await buildTestFit();
    const result = await FitOps.root(binary, { changeDtModel: true, replaceKernel: false });
    const tree = FDT.parse(result);
    const origNode = FDT.findNode(tree.root, ['images', 'orig']);
    assert.ok(origNode, 'Expected /images/orig');
    const origFdt = origNode.children.find(c => c.name === 'fdt-1');
    assert.ok(origFdt, 'Expected /images/orig/fdt-1');
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
