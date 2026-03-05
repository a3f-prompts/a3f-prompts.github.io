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
      const type = FDT.getStringProperty(img, 'type') || 'unknown';
      const desc = FDT.getStringProperty(img, 'description') || '';
      const data = FDT.getProperty(img, 'data');
      const size = data ? data.byteLength : 0;
      const compression = FDT.getStringProperty(img, 'compression') || 'none';
      return { name: img.name, type, description: desc, size, compression };
    });

    const desc = FDT.getStringProperty(tree.root, 'description') || '';

    return { valid: true, tree, images, description: desc, error: null };
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
      return type === 'kernel';
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
   * Recalculate hashes for all image nodes under /images.
   * Supports crc32 and sha256.
   */
  async function recalculateHashes(tree) {
    const imagesNode = FDT.findNode(tree.root, ['images']);
    if (!imagesNode) return;

    for (const img of imagesNode.children) {
      const data = FDT.getProperty(img, 'data');
      if (!data) continue;

      for (const hashNode of img.children) {
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
          // MD5 not available in Web Crypto — remove the hash node value
          // so it doesn't contain stale data
          const prop = hashNode.properties.find(p => p.name === 'value');
          if (prop) prop.data = new Uint8Array(0);
        }
      }
    }
  }

  /**
   * Full rooting operation: modify DT model, replace kernel, fix hashes,
   * remove signatures, serialize.
   */
  async function root(buffer, options) {
    const result = validate(buffer);
    if (!result.valid) {
      throw new Error(result.error);
    }

    const tree = result.tree;

    if (options.changeDtModel) {
      changeDtModel(tree, 'rooted by ifitfitsisits.com');
    }

    if (options.replaceKernel && options.kernelData) {
      replaceKernel(tree, new Uint8Array(options.kernelData));
    }

    // Remove signatures first (can't recalculate without private key)
    removeSignatures(tree);

    // Recalculate hashes
    await recalculateHashes(tree);

    // Serialize the modified FIT
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
