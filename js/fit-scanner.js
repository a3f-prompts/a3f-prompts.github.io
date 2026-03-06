/**
 * Scan a binary image (e.g. HD/SD card dump) for embedded FIT images.
 *
 * Walks the file looking for FDT magic (0xd00dfeed), extracts totalsize,
 * and checks for a /configurations node to confirm it's a FIT (not just a DTB).
 * Works on the ArrayBuffer directly to conserve RAM.
 */

const FitScanner = (() => {
  const FDT_MAGIC = 0xd00dfeed;

  /**
   * Quick check: does this DTB at the given offset contain a /configurations node?
   * Scans the structure block for the "configurations" node name.
   * Node names live in the struct block (after FDT_BEGIN_NODE tokens), not the strings block.
   */
  function hasFitStructure(dv, u8, offset, totalsize) {
    if (offset + 40 > u8.byteLength) return false;
    if (offset + totalsize > u8.byteLength) return false;

    const structOff = offset + dv.getUint32(offset + 8);
    const structSize = dv.getUint32(offset + 36);
    const structEnd = structOff + structSize;

    if (structEnd > u8.byteLength) return false;

    // Search for "configurations\0" in the structure block
    const target = new TextEncoder().encode('configurations\0');
    const end = structEnd - target.length;
    for (let i = structOff; i <= end; i++) {
      let match = true;
      for (let j = 0; j < target.length; j++) {
        if (u8[i + j] !== target[j]) { match = false; break; }
      }
      if (match) return true;
    }
    return false;
  }

  /**
   * Extract a description from the FIT at the given offset, if possible.
   * Does a minimal parse to find the root description property.
   */
  function extractDescription(dv, u8, offset, totalsize) {
    try {
      const slice = u8.slice(offset, offset + Math.min(totalsize, 4096));
      const tree = FDT.parse(slice);
      return FDT.getStringProperty(tree.root, 'description') || '';
    } catch {
      return '';
    }
  }

  /**
   * Scan buffer for FIT images. Returns array of:
   *   { offset, totalsize, description }
   *
   * Only includes DTBs that have a /configurations node (i.e. actual FIT images).
   * Scans at 4-byte aligned boundaries for FDT magic.
   */
  function scan(buffer) {
    const u8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    const results = [];

    for (let i = 0; i + 8 <= u8.byteLength; i += 4) {
      if (dv.getUint32(i) !== FDT_MAGIC) continue;

      const totalsize = dv.getUint32(i + 4);

      // Sanity checks
      if (totalsize < 48) continue;  // too small for a valid DTB
      if (totalsize > 64 * 1024 * 1024) continue;  // cap at 64MB
      if (i + totalsize > u8.byteLength) continue;

      if (!hasFitStructure(dv, u8, i, totalsize)) continue;

      const description = extractDescription(dv, u8, i, totalsize);
      results.push({ offset: i, totalsize, description });

      // Skip past this FIT to avoid finding nested DTBs within it
      i += totalsize - 4;  // -4 because loop adds 4
    }

    return results;
  }

  /**
   * Extract a FIT image from the buffer at the given offset/size.
   */
  function extract(buffer, offset, totalsize) {
    const u8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return u8.slice(offset, offset + totalsize);
  }

  /**
   * Splice a modified FIT back into the original buffer.
   * If the new FIT is the same size, it's a direct replacement.
   * If different, rebuilds the buffer with the new data.
   */
  function splice(originalBuffer, offset, originalSize, newFitData) {
    const orig = originalBuffer instanceof Uint8Array ? originalBuffer : new Uint8Array(originalBuffer);
    const newFit = newFitData instanceof Uint8Array ? newFitData : new Uint8Array(newFitData);

    if (newFit.byteLength === originalSize) {
      // Same size — replace in place
      const result = new Uint8Array(orig);
      result.set(newFit, offset);
      return result;
    }

    // Different size — rebuild
    const result = new Uint8Array(orig.byteLength - originalSize + newFit.byteLength);
    result.set(orig.subarray(0, offset), 0);
    result.set(newFit, offset);
    result.set(orig.subarray(offset + originalSize), offset + newFit.byteLength);
    return result;
  }

  return { scan, extract, splice };
})();
