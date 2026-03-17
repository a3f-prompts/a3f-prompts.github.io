/**
 * Test helpers: load browser globals (FDT, FitOps) into Node.js,
 * and provide utilities for building test FIT images.
 */

const { readFileSync } = require('fs');
const { join } = require('path');
const { webcrypto } = require('crypto');

// Polyfill browser globals for the library code
globalThis.crypto = webcrypto;
globalThis.TextEncoder = TextEncoder;
globalThis.TextDecoder = TextDecoder;

// Load browser modules by evaluating them (they assign to global IIFE-style)
const fdtCode = readFileSync(join(__dirname, 'fdt-parser.js'), 'utf8');
const shaFallbackCode = readFileSync(join(__dirname, 'sha-fallback.js'), 'utf8');
const fitOpsCode = readFileSync(join(__dirname, 'fit-ops.js'), 'utf8');

// FDT is an IIFE assigned to const — extract it
const FDT = new Function(fdtCode.replace('const FDT =', 'return') )();
globalThis.FDT = FDT;

// ShaFallback must be global before FitOps
const ShaFallback = new Function(shaFallbackCode.replace('const ShaFallback =', 'return'))();
globalThis.ShaFallback = ShaFallback;

// FitOps depends on FDT and ShaFallback being global
const FitOps = new Function(fitOpsCode.replace('const FitOps =', 'return'))();

/**
 * Build a minimal signed FIT image (DTB binary) for testing.
 *
 * Structure mirrors the Python test fixture's image.its:
 *   / { description, images { kernel { data, type, compression, hash-1 { algo, value } },
 *       fdt-1 { ... } }, configurations { conf-1 { signature-1 { hashed-nodes } } } }
 */
async function buildTestFit(kernelData = null, fdtData = null) {
  const kernel = kernelData || new TextEncoder().encode('hallo\n');
  const fdt = fdtData || buildMinimalDtb('Test Board');

  // Compute SHA-256 hashes
  const kernelHash = new Uint8Array(await webcrypto.subtle.digest('SHA-256', kernel));
  const fdtHash = new Uint8Array(await webcrypto.subtle.digest('SHA-256', fdt));

  const enc = new TextEncoder();

  function strProp(s) { return enc.encode(s + '\0'); }
  function u32Prop(v) {
    const b = new ArrayBuffer(4);
    new DataView(b).setUint32(0, v);
    return new Uint8Array(b);
  }

  // Build hashed-nodes as null-separated string list
  function hashedNodesProp(imageName) {
    return enc.encode(
      `/images/${imageName}\0/images/${imageName}/hash-1\0`
    );
  }

  const tree = {
    header: { version: 17, last_comp_version: 16, boot_cpuid_phys: 0 },
    reserveEntries: [],
    root: {
      name: '',
      properties: [
        { name: 'description', data: strProp('Signed FIT Image') },
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
              children: [
                {
                  name: 'hash-1',
                  properties: [
                    { name: 'algo', data: strProp('sha256') },
                    { name: 'value', data: kernelHash },
                  ],
                  children: [],
                },
              ],
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
              children: [
                {
                  name: 'hash-1',
                  properties: [
                    { name: 'algo', data: strProp('sha256') },
                    { name: 'value', data: fdtHash },
                  ],
                  children: [],
                },
              ],
            },
          ],
        },
        {
          name: 'configurations',
          properties: [
            { name: 'default', data: strProp('conf-1') },
          ],
          children: [
            {
              name: 'conf-1',
              properties: [
                { name: 'description', data: strProp('Boot Configuration') },
                { name: 'kernel', data: strProp('kernel') },
                { name: 'fdt', data: strProp('fdt-1') },
              ],
              children: [
                {
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
                },
              ],
            },
          ],
        },
      ],
    },
  };

  return { tree, binary: FDT.serialize(tree) };
}

/**
 * Build a minimal DTB for use as nested device tree data.
 */
function buildMinimalDtb(model) {
  const enc = new TextEncoder();
  const tree = {
    header: { version: 17, last_comp_version: 16, boot_cpuid_phys: 0 },
    reserveEntries: [],
    root: {
      name: '',
      properties: [
        { name: 'model', data: enc.encode(model + '\0') },
        { name: 'compatible', data: enc.encode('test,board\0') },
      ],
      children: [],
    },
  };
  return FDT.serialize(tree);
}

/**
 * Build a FIT image with external data layout.
 * The DTB structure comes first, then data is appended after totalsize.
 */
async function buildExternalDataFit(kernelData = null) {
  const kernel = kernelData || new TextEncoder().encode('hallo\n');
  const fdt = buildMinimalDtb('Test Board');
  const enc = new TextEncoder();

  function strProp(s) { return enc.encode(s + '\0'); }
  function u32Prop(v) {
    const b = new ArrayBuffer(4);
    new DataView(b).setUint32(0, v);
    return new Uint8Array(b);
  }

  const kernelHash = new Uint8Array(await webcrypto.subtle.digest('SHA-256', kernel));
  const fdtHash = new Uint8Array(await webcrypto.subtle.digest('SHA-256', fdt));

  // Build tree with data-offset/data-size instead of inline data
  const tree = {
    header: { version: 17, last_comp_version: 16, boot_cpuid_phys: 0 },
    reserveEntries: [],
    root: {
      name: '',
      properties: [
        { name: 'description', data: strProp('Signed FIT Image') },
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
                { name: 'data-offset', data: u32Prop(0) }, // offset 0 from ext base
                { name: 'data-size', data: u32Prop(kernel.length) },
                { name: 'type', data: strProp('kernel') },
                { name: 'compression', data: strProp('none') },
              ],
              children: [
                {
                  name: 'hash-1',
                  properties: [
                    { name: 'algo', data: strProp('sha256') },
                    { name: 'value', data: kernelHash },
                  ],
                  children: [],
                },
              ],
            },
            {
              name: 'fdt-1',
              properties: [
                { name: 'description', data: strProp('Device Tree') },
                { name: 'data-offset', data: u32Prop(FDT.align4(kernel.length)) },
                { name: 'data-size', data: u32Prop(fdt.length) },
                { name: 'type', data: strProp('flat_dt') },
                { name: 'compression', data: strProp('none') },
              ],
              children: [
                {
                  name: 'hash-1',
                  properties: [
                    { name: 'algo', data: strProp('sha256') },
                    { name: 'value', data: fdtHash },
                  ],
                  children: [],
                },
              ],
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
                { name: 'kernel', data: strProp('kernel') },
                { name: 'fdt', data: strProp('fdt-1') },
              ],
              children: [
                {
                  name: 'signature-1',
                  properties: [
                    { name: 'algo', data: strProp('sha256,rsa2048') },
                    { name: 'hashed-nodes', data: enc.encode(
                      '/images/kernel\0/images/kernel/hash-1\0' +
                      '/images/fdt-1\0/images/fdt-1/hash-1\0'
                    )},
                  ],
                  children: [],
                },
              ],
            },
          ],
        },
      ],
    },
  };

  // Serialize the DTB part
  const dtbPart = FDT.serialize(tree);

  // Append external data after the DTB
  const kernelAligned = FDT.align4(kernel.length);
  const extData = new Uint8Array(kernelAligned + fdt.length);
  extData.set(kernel, 0);
  extData.set(fdt, kernelAligned);

  // Concatenate DTB + external data
  const full = new Uint8Array(dtbPart.length + extData.length);
  full.set(dtbPart, 0);
  full.set(extData, dtbPart.length);

  return full;
}

module.exports = { FDT, FitOps, ShaFallback, buildTestFit, buildMinimalDtb, buildExternalDataFit };
