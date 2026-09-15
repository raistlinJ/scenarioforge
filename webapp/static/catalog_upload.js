/* Package folders as a single ZIP part, avoiding large multipart browser failures.
 * Stored entries avoid compression dependencies; read one file at a time.
 */
(function (root) {
  'use strict';
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ ((c & 1) ? 0xedb88320 : 0);
    table[n] = c;
  }
  async function readFile(file) {
    try {
      return await file.arrayBuffer();
    } catch (firstError) {
      // Retry through Safari's older file-reading API before giving up.
      return await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(reader.error || firstError);
        reader.onabort = () => reject(new Error('File read aborted'));
        reader.readAsArrayBuffer(file);
      });
    }
  }
  root.catalogFolderNeedsMultipart = function (files) {
    // ZIP32 has format limits. Larger folders can still use the server's
    // streaming multipart importer, whose ZIP writer supports ZIP64.
    const encoder = new TextEncoder();
    const size = files.reduce((sum, file) => sum + file.size + 76
      + 2 * encoder.encode(file.webkitRelativePath || '').length, 22);
    return files.length > 65535 || size >= 0xffffffff;
  };
  root.catalogFolderZip = async function (files, onProgress = () => {}) {
    if (!files.length || files.length > 65535) throw new Error('Unsupported ZIP file count');
    const bodies = [], directory = [], names = new Set();
    let offset = 0, directorySize = 0;
    for (const file of files) {
      const path = String(file.webkitRelativePath || '').replace(/\\/g, '/');
      if (!path.includes('/') || path.startsWith('/') || path.split('/').some(p => !p || p === '..' || p === '.') || names.has(path)) {
        throw new Error('Invalid or duplicate folder path');
      }
      names.add(path);
      const name = new TextEncoder().encode(path);
      if (name.length > 65535 || offset + file.size + name.length + 30 >= 0xffffffff) throw new Error('Folder exceeds ZIP size limit');
      const current = names.size;
      onProgress({ current, total: files.length, path });
      let bytes;
      try {
        bytes = new Uint8Array(await readFile(file));
        if (bytes.length !== file.size) throw new Error('Incomplete file read');
      } catch (error) {
        throw new Error(`Cannot read file ${current} of ${files.length}: ${path} (${error.message || error})`);
      }
      let crc = 0xffffffff;
      for (const byte of bytes) crc = (crc >>> 8) ^ table[(crc ^ byte) & 255];
      crc = (crc ^ 0xffffffff) >>> 0;
      const local = new Uint8Array(30 + name.length), lv = new DataView(local.buffer);
      lv.setUint32(0, 0x04034b50, true);
      lv.setUint16(4, 20, true);
      lv.setUint16(6, 0x800, true);
      lv.setUint16(12, 33, true);
      lv.setUint32(14, crc, true);
      lv.setUint32(18, bytes.length, true);
      lv.setUint32(22, bytes.length, true);
      lv.setUint16(26, name.length, true);
      local.set(name, 30);
      const central = new Uint8Array(46 + name.length), cv = new DataView(central.buffer);
      cv.setUint32(0, 0x02014b50, true);
      cv.setUint16(4, 20, true);
      central.set(local.subarray(4, 30), 6);
      cv.setUint32(42, offset, true);
      central.set(name, 46);
      bodies.push(local, new Blob([bytes]));
      directory.push(central);
      offset += local.length + bytes.length;
      directorySize += central.length;
    }
    if (offset + directorySize >= 0xffffffff) throw new Error('Folder exceeds ZIP size limit');
    const end = new Uint8Array(22), ev = new DataView(end.buffer);
    ev.setUint32(0, 0x06054b50, true);
    ev.setUint16(8, files.length, true);
    ev.setUint16(10, files.length, true);
    ev.setUint32(12, directorySize, true);
    ev.setUint32(16, offset, true);
    return new Blob([...bodies, ...directory, end], { type: 'application/zip' });
  };
})(globalThis);
