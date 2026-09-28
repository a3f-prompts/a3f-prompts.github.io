/**
 * FDT (Flattened Device Tree) binary parser and serializer.
 *
 * DTB format: header (40 bytes) + memory reservation block +
 * structure block (tokens + node/property data) + strings block.
 * All integers are big-endian.
 */

const FDT = (() => {
  const MAGIC = 0xd00dfeed;
  const TOKEN = {
    BEGIN_NODE: 1,
    END_NODE: 2,
    PROP: 3,
    NOP: 4,
    END: 9,
  };

  function align4(n) {
    return (n + 3) & ~3;
  }

  /**
   * Parse a DTB binary (ArrayBuffer or Uint8Array) into a tree structure.
   * Returns { header, reserveEntries, root }.
   */
  function parse(buffer) {
    const u8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);

    const magic = dv.getUint32(0);
    if (magic !== MAGIC) {
      throw new Error(`Not a DTB: bad magic 0x${magic.toString(16)} (expected 0xd00dfeed)`);
    }

    const header = {
      magic,
      totalsize: dv.getUint32(4),
      off_dt_struct: dv.getUint32(8),
      off_dt_strings: dv.getUint32(12),
      off_mem_rsvmap: dv.getUint32(16),
      version: dv.getUint32(20),
      last_comp_version: dv.getUint32(24),
      boot_cpuid_phys: dv.getUint32(28),
      size_dt_strings: dv.getUint32(32),
      size_dt_struct: dv.getUint32(36),
    };

    // Parse memory reservation block
    const reserveEntries = [];
    let rsvOff = header.off_mem_rsvmap;
    while (rsvOff + 16 <= u8.byteLength) {
      const addrHi = dv.getUint32(rsvOff);
      const addrLo = dv.getUint32(rsvOff + 4);
      const sizeHi = dv.getUint32(rsvOff + 8);
      const sizeLo = dv.getUint32(rsvOff + 12);
      rsvOff += 16;
      if (addrHi === 0 && addrLo === 0 && sizeHi === 0 && sizeLo === 0) break;
      reserveEntries.push({ addrHi, addrLo, sizeHi, sizeLo });
    }

    // Parse structure block
    const stringsStart = header.off_dt_strings;
    let offset = header.off_dt_struct;

    function readString(nameoff) {
      let end = stringsStart + nameoff;
      while (end < u8.byteLength && u8[end] !== 0) end++;
      return new TextDecoder().decode(u8.slice(stringsStart + nameoff, end));
    }

    function readNodeName() {
      let end = offset;
      while (end < u8.byteLength && u8[end] !== 0) end++;
      const name = new TextDecoder().decode(u8.slice(offset, end));
      offset = align4(end + 1);
      return name;
    }

    function parseNode() {
      const name = readNodeName();
      const node = { name, properties: [], children: [] };

      while (offset < u8.byteLength) {
        const token = dv.getUint32(offset);
        offset += 4;

        if (token === TOKEN.BEGIN_NODE) {
          node.children.push(parseNode());
        } else if (token === TOKEN.END_NODE) {
          return node;
        } else if (token === TOKEN.PROP) {
          const len = dv.getUint32(offset);
          const nameoff = dv.getUint32(offset + 4);
          offset += 8;
          const propName = readString(nameoff);
          const data = u8.slice(offset, offset + len);
          offset += align4(len);
          node.properties.push({ name: propName, data: new Uint8Array(data) });
        } else if (token === TOKEN.NOP) {
          // skip
        } else if (token === TOKEN.END) {
          return node;
        }
      }
      return node;
    }

    // Read first token — should be BEGIN_NODE
    const firstToken = dv.getUint32(offset);
    offset += 4;
    if (firstToken !== TOKEN.BEGIN_NODE) {
      throw new Error('Expected FDT_BEGIN_NODE at start of structure block');
    }

    const root = parseNode();

    // Preserve original strings block so serialization keeps the same ordering
    const origStrings = u8.slice(stringsStart, stringsStart + header.size_dt_strings);

    return { header, reserveEntries, root, origStrings: new Uint8Array(origStrings) };
  }

  /**
   * Serialize a parsed tree back to a DTB binary (Uint8Array).
   */
  function serialize(tree) {
    const { header, reserveEntries, root } = tree;

    // Build strings table — reuse original ordering if available, append new strings
    const stringMap = new Map();
    const strings = [];
    let stringsSize = 0;

    // Seed from original strings block to preserve ordering (critical for hashed-strings)
    if (tree.origStrings && tree.origStrings.byteLength > 0) {
      const orig = tree.origStrings;
      let i = 0;
      while (i < orig.byteLength) {
        let end = i;
        while (end < orig.byteLength && orig[end] !== 0) end++;
        const name = new TextDecoder().decode(orig.slice(i, end));
        if (name && !stringMap.has(name)) {
          stringMap.set(name, stringsSize);
          const encoded = new TextEncoder().encode(name);
          strings.push(encoded);
          stringsSize += encoded.byteLength + 1;
        }
        i = end + 1;
      }
    }

    function collectStrings(node) {
      for (const prop of node.properties) {
        if (!stringMap.has(prop.name)) {
          stringMap.set(prop.name, stringsSize);
          const encoded = new TextEncoder().encode(prop.name);
          strings.push(encoded);
          stringsSize += encoded.byteLength + 1; // +1 for null terminator
        }
      }
      for (const child of node.children) {
        collectStrings(child);
      }
    }
    collectStrings(root);

    // Calculate structure block size
    function calcStructSize(node) {
      // BEGIN_NODE(4) + name(aligned) + properties + children + END_NODE(4)
      let size = 4; // BEGIN_NODE
      const nameBytes = new TextEncoder().encode(node.name);
      size += align4(nameBytes.byteLength + 1);
      for (const prop of node.properties) {
        size += 4 + 8 + align4(prop.data.byteLength); // token + len+nameoff + data
      }
      for (const child of node.children) {
        size += calcStructSize(child);
      }
      size += 4; // END_NODE
      return size;
    }

    const structSize = calcStructSize(root) + 4; // +4 for FDT_END

    // Layout
    const rsvmapOff = 40; // header size
    const rsvmapSize = (reserveEntries.length + 1) * 16; // +1 for terminator
    const structOff = rsvmapOff + rsvmapSize;
    const stringsOff = structOff + structSize;
    const totalSize = stringsOff + stringsSize;

    const buf = new ArrayBuffer(totalSize);
    const dv = new DataView(buf);
    const u8 = new Uint8Array(buf);

    // Write header
    dv.setUint32(0, MAGIC);
    dv.setUint32(4, totalSize);
    dv.setUint32(8, structOff);
    dv.setUint32(12, stringsOff);
    dv.setUint32(16, rsvmapOff);
    dv.setUint32(20, header.version || 17);
    dv.setUint32(24, header.last_comp_version || 16);
    dv.setUint32(28, header.boot_cpuid_phys || 0);
    dv.setUint32(32, stringsSize);
    dv.setUint32(36, structSize);

    // Write memory reservation block
    let off = rsvmapOff;
    for (const entry of reserveEntries) {
      dv.setUint32(off, entry.addrHi); off += 4;
      dv.setUint32(off, entry.addrLo); off += 4;
      dv.setUint32(off, entry.sizeHi); off += 4;
      dv.setUint32(off, entry.sizeLo); off += 4;
    }
    // Terminator (16 bytes of zero — already zeroed)
    off += 16;

    // Write structure block
    off = structOff;

    function writeNode(node) {
      dv.setUint32(off, TOKEN.BEGIN_NODE); off += 4;
      const nameBytes = new TextEncoder().encode(node.name);
      u8.set(nameBytes, off);
      off += nameBytes.byteLength;
      u8[off] = 0; // null terminator
      off++;
      // align
      while (off % 4 !== 0) { u8[off] = 0; off++; }

      for (const prop of node.properties) {
        dv.setUint32(off, TOKEN.PROP); off += 4;
        dv.setUint32(off, prop.data.byteLength); off += 4;
        dv.setUint32(off, stringMap.get(prop.name)); off += 4;
        u8.set(prop.data, off);
        off += prop.data.byteLength;
        while (off % 4 !== 0) { u8[off] = 0; off++; }
      }

      for (const child of node.children) {
        writeNode(child);
      }

      dv.setUint32(off, TOKEN.END_NODE); off += 4;
    }

    writeNode(root);
    dv.setUint32(off, TOKEN.END);

    // Write strings block
    off = stringsOff;
    for (const s of strings) {
      u8.set(s, off);
      off += s.byteLength;
      u8[off] = 0; // null terminator
      off++;
    }

    return new Uint8Array(buf);
  }

  /**
   * Byte offset of a property's value inside a serialized blob.
   *
   * parse() throws offsets away, but the entry-address bypass has to know
   * where in the blob a property ends up: the address it writes into an
   * image's entry is where the FIT itself is loaded plus exactly this.  Walks
   * the structure block instead of searching the blob for the value, which
   * may well occur a second time inside some image's data.
   *
   * Returns null if the node or the property is not there.
   */
  function propertyOffset(buffer, path, propName) {
    const u8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    const stringsStart = dv.getUint32(12);
    const structStart = dv.getUint32(8);
    const structEnd = Math.min(structStart + dv.getUint32(36), u8.byteLength);
    const decoder = new TextDecoder();

    function readString(nameoff) {
      let end = stringsStart + nameoff;
      while (end < u8.byteLength && u8[end] !== 0) end++;
      return decoder.decode(u8.slice(stringsStart + nameoff, end));
    }

    // Names of the nodes the walk is currently inside, starting at the
    // (unnamed) root, so the wanted path sits one level in.
    const here = [];
    const inTarget = () =>
      here.length === path.length + 1 && path.every((name, i) => here[i + 1] === name);

    let offset = structStart;
    while (offset + 4 <= structEnd) {
      const token = dv.getUint32(offset);
      offset += 4;

      if (token === TOKEN.BEGIN_NODE) {
        let end = offset;
        while (end < u8.byteLength && u8[end] !== 0) end++;
        here.push(decoder.decode(u8.slice(offset, end)));
        offset = align4(end + 1);
      } else if (token === TOKEN.END_NODE) {
        here.pop();
      } else if (token === TOKEN.PROP) {
        const len = dv.getUint32(offset);
        const nameoff = dv.getUint32(offset + 4);
        offset += 8;
        if (inTarget() && readString(nameoff) === propName) return offset;
        offset += align4(len);
      } else if (token === TOKEN.END) {
        break;
      }
      // NOP: the token is all there is to skip
    }

    return null;
  }

  /**
   * Find a child node by name path (e.g. ["images", "kernel@1"]).
   */
  function findNode(root, path) {
    let node = root;
    for (const segment of path) {
      const child = node.children.find(c => c.name === segment);
      if (!child) return null;
      node = child;
    }
    return node;
  }

  /**
   * Get a property value from a node by name. Returns Uint8Array or null.
   */
  function getProperty(node, name) {
    const prop = node.properties.find(p => p.name === name);
    return prop ? prop.data : null;
  }

  /**
   * Set a property value on a node. Creates the property if it doesn't exist.
   */
  function setProperty(node, name, data) {
    const prop = node.properties.find(p => p.name === name);
    const u8 = (typeof data === 'string')
      ? new TextEncoder().encode(data + '\0')
      : (data instanceof Uint8Array ? data : new Uint8Array(data));
    if (prop) {
      prop.data = u8;
    } else {
      node.properties.push({ name, data: u8 });
    }
  }

  /**
   * Get a string property (strip trailing null bytes).
   */
  function getStringProperty(node, name) {
    const data = getProperty(node, name);
    if (!data) return null;
    let end = data.byteLength;
    while (end > 0 && data[end - 1] === 0) end--;
    return new TextDecoder().decode(data.slice(0, end));
  }

  /**
   * Get a stringlist property as an array of strings (split on null bytes).
   */
  function getStringListProperty(node, name) {
    const data = getProperty(node, name);
    if (!data) return null;
    let end = data.byteLength;
    while (end > 0 && data[end - 1] === 0) end--;
    if (end === 0) return [];
    const raw = new TextDecoder().decode(data.slice(0, end));
    return raw.split('\0');
  }

  /**
   * Remove a child node by name. Returns true if removed.
   */
  function removeChild(parent, childName) {
    const idx = parent.children.findIndex(c => c.name === childName);
    if (idx >= 0) {
      parent.children.splice(idx, 1);
      return true;
    }
    return false;
  }

  /**
   * Deep-clone a node (properties get new Uint8Array copies).
   */
  function cloneNode(node) {
    return {
      name: node.name,
      properties: node.properties.map(p => ({
        name: p.name,
        data: new Uint8Array(p.data),
      })),
      children: node.children.map(c => cloneNode(c)),
    };
  }

  /**
   * Resolve external data references (data-offset/data-size or data-position)
   * into inline data properties. For FIT images with external data layout.
   */
  function resolveExternalData(root, buffer) {
    const u8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    const extDataBase = dv.getUint32(4); // totalsize = start of external data

    function resolve(node) {
      const propMap = {};
      for (const p of node.properties) {
        propMap[p.name] = p;
      }

      const hasOffset = 'data-offset' in propMap;
      const hasSize = 'data-size' in propMap;
      const hasPosition = 'data-position' in propMap;

      if (hasOffset || hasSize || hasPosition) {
        let offset = null;
        if (hasOffset) {
          offset = extDataBase + new DataView(propMap['data-offset'].data.buffer,
            propMap['data-offset'].data.byteOffset, 4).getUint32(0);
        } else if (hasPosition) {
          offset = new DataView(propMap['data-position'].data.buffer,
            propMap['data-position'].data.byteOffset, 4).getUint32(0);
        }

        let size = null;
        if (hasSize) {
          size = new DataView(propMap['data-size'].data.buffer,
            propMap['data-size'].data.byteOffset, 4).getUint32(0);
        }

        const drop = new Set(['data-offset', 'data-size', 'data-position']);
        if (offset !== null && size !== null) {
          const inlineData = new Uint8Array(u8.slice(offset, offset + size));
          node.properties = node.properties.filter(p => !drop.has(p.name));
          node.properties.push({ name: 'data', data: inlineData });
        } else {
          node.properties = node.properties.filter(p => !drop.has(p.name));
        }
      }

      for (const child of node.children) {
        resolve(child);
      }
    }

    resolve(root);
  }

  return {
    MAGIC,
    TOKEN,
    parse,
    serialize,
    propertyOffset,
    findNode,
    getProperty,
    setProperty,
    getStringProperty,
    getStringListProperty,
    removeChild,
    cloneNode,
    resolveExternalData,
    align4,
  };
})();
