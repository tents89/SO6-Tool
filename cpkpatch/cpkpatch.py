#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cpkpatch.py - CRI CPK in-place incremental archive patcher.

This tool does not rebuild the whole CPK. It writes replacement files into the original free space, appends to the end when necessary, and updates the TOC offset/size fields in place. Even a 1.4 GB CPK only takes a few seconds.

Usage:
  python cpkpatch.py info    -p data000.cpk
  python cpkpatch.py list    -p data000.cpk [-f filter]
  python cpkpatch.py patch   -p data000.cpk -i new_files [--backup] [-o output.cpk]
"""
import argparse
import os
import shutil
import struct
import sys
import time

STORAGE_MASK = 0xF0
STORAGE_NONE = 0x00
STORAGE_ZERO = 0x10
STORAGE_CONSTANT = 0x30
STORAGE_PERROW = 0x50
TYPE_MASK = 0x0F

CODES = {
    0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i",
    6: "Q", 7: "q", 8: "f", 9: "d", 0xA: "I", 0xB: "II",
}
TYPE_STRING = 0xA
TYPE_DATA = 0xB
INT_CODES = "BbHhIiQq"


def crypt_utf(data):
    m, t = 0x655F, 0x4115
    out = bytearray(data)
    for i in range(len(out)):
        out[i] ^= m & 0xFF
        m = (m * t) & 0xFFFFFFFF
    return bytes(out)


class Cell:
    __slots__ = ("offset", "code", "name", "row")

    def __init__(self, offset, code, name, row):
        self.offset = offset
        self.code = code
        self.name = name
        self.row = row

    @property
    def width(self):
        return struct.calcsize(">" + self.code)

def poke(packet, cell, value):
    if cell is None:
        raise ValueError("cell is None")
    if cell.code not in INT_CODES:
        raise ValueError("%s is not an integer cell" % cell.name)
    lo, hi = (0, (1 << (cell.width * 8)) - 1) if cell.code.isupper() else \
             (-(1 << (cell.width * 8 - 1)), (1 << (cell.width * 8 - 1)) - 1)
    if not lo <= value <= hi:
        raise ValueError("%s = %d is out of range for %s" % (cell.name, value, cell.code))
    struct.pack_into(">" + cell.code, packet, cell.offset, value)


class Utf:
    def __init__(self, packet, encoding="utf-8"):
        if packet[0:4] != b"@UTF":
            packet = crypt_utf(packet)
        if packet[0:4] != b"@UTF":
            raise ValueError("not an @UTF packet")
        self.buf = bytes(packet)
        self.encoding = encoding
        self.size = struct.unpack_from(">I", self.buf, 4)[0]
        rows, strs, data, name, self.num_cols, self.row_length, self.num_rows = \
            struct.unpack_from(">IIIIHHI", self.buf, 8)
        self.rows_offset = rows + 8
        self.string_offset = strs + 8
        self.data_offset = data + 8
        self.table_name = self.string(name)

        self.columns = []
        p = 8 + 0x18
        row_pos = 0
        for _ in range(self.num_cols):
            flags = self.buf[p]
            p += 1
            cname = self.string(struct.unpack_from(">I", self.buf, p)[0])
            p += 4
            store = flags & STORAGE_MASK
            const, cell_at = None, None
            if store == STORAGE_CONSTANT:
                const, p = self._read(flags, p)
            elif store == STORAGE_PERROW:
                cell_at = row_pos
                row_pos += struct.calcsize(">" + CODES[flags & TYPE_MASK])
            self.columns.append({"name": cname, "flags": flags,
                                 "const": const, "cell": cell_at})
        if row_pos != self.row_length:
            raise ValueError("row layout mismatch: %d != %d" % (row_pos, self.row_length))
        self._by_name = {c["name"]: c for c in self.columns}

    def string(self, off):
        end = self.buf.index(b"\0", self.string_offset + off)
        return self.buf[self.string_offset + off:end].decode(self.encoding, "replace")

    def _read(self, flags, p):
        code = CODES[flags & TYPE_MASK]
        vals = struct.unpack_from(">" + code, self.buf, p)
        p += struct.calcsize(">" + code)
        t = flags & TYPE_MASK
        if t == TYPE_STRING:
            return self.string(vals[0]), p
        if t == TYPE_DATA:
            return (self.data_offset + vals[0], vals[1]), p
        return vals[0], p

    def get(self, row, name):
        c = self._by_name.get(name)
        if c is None:
            return None
        store = c["flags"] & STORAGE_MASK
        if store == STORAGE_CONSTANT:
            return c["const"]
        if store in (STORAGE_NONE, STORAGE_ZERO):
            return None
        if not 0 <= row < self.num_rows:
            raise IndexError(row)
        return self._read(c["flags"], self.rows_offset + row * self.row_length + c["cell"])[0]

    def cell(self, row, name):
        c = self._by_name.get(name)
        if c is None or c["cell"] is None:
            return None
        code = CODES[c["flags"] & TYPE_MASK]
        if code not in INT_CODES:
            return None
        if not 0 <= row < self.num_rows:
            raise IndexError(row)
        return Cell(self.rows_offset + row * self.row_length + c["cell"], code, name, row)

ALIGN = 0x800
NO_OFFSET = 0xFFFFFFFFFFFFFFFF


class Section:
    """A @UTF section inside a CPK archive (CPK / TOC / ITOC / ETOC / GTOC)."""

    def __init__(self, magic, offset, packet, encrypted, encoding="utf-8", unk1=0xFF):
        self.magic = magic
        self.offset = offset            # section start (magic position)
        self.packet = bytearray(packet)  # decrypted @UTF payload
        self.encrypted = encrypted
        self.unk1 = unk1
        self.utf = Utf(bytes(packet), encoding)
        self.dirty = False

    @property
    def data_pos(self):
        return self.offset + 0x10       # packet position in the file

    def raw_packet(self):
        return crypt_utf(bytes(self.packet)) if self.encrypted else bytes(self.packet)

    def write_back(self, f):
        """Overwrite the original position when the size is unchanged."""
        f.seek(self.data_pos)
        f.write(self.raw_packet())

    def write_full(self, f, offset):
        """Move the whole section (including the 16-byte header) to a new position and return the end offset."""
        raw = self.raw_packet()
        f.seek(offset)
        f.write(self.magic)
        f.write(struct.pack("<i", self.unk1))
        f.write(struct.pack("<q", len(raw)))
        f.write(raw)
        self.offset = offset
        return offset + 0x10 + len(raw)



class Entry:
    """A file entry in the TOC."""
    __slots__ = ("index", "dirname", "filename", "path", "offset", "size",
                 "extract_size", "add_offset", "slot_end", "id")

    def __init__(self, index):
        self.index = index
        self.dirname = ""
        self.filename = ""
        self.path = ""
        self.offset = 0
        self.size = 0
        self.extract_size = 0
        self.add_offset = 0
        self.slot_end = 0
        self.id = None

    @property
    def slot(self):
        return self.slot_end - self.offset


class Cpk:
    def __init__(self, path, encoding="utf-8"):
        self.path = path
        self.encoding = encoding
        self.file_size = os.path.getsize(path)
        self.sections = {}
        self.entries = []
        with open(path, "rb") as f:
            self._read_header(f)
            self._read_toc(f)
        self._compute_slots()

    # ---------- Reading ----------
    def _read_section(self, f, offset, magic):
        f.seek(offset)
        got = f.read(4)
        if got != magic:
            raise ValueError("%s section signature mismatch @0x%X: %r" % (magic, offset, got))
        unk1 = struct.unpack("<i", f.read(4))[0]
        size = struct.unpack("<q", f.read(8))[0]
        packet = f.read(size)
        encrypted = packet[0:4] != b"@UTF"
        if encrypted:
            packet = crypt_utf(packet)
        return Section(magic, offset, packet, encrypted, self.encoding, unk1)

    def _read_header(self, f):
        cpk = self._read_section(f, 0, b"CPK ")
        self.sections["CPK"] = cpk
        u = cpk.utf
        self.toc_offset = u.get(0, "TocOffset")
        self.etoc_offset = u.get(0, "EtocOffset")
        self.itoc_offset = u.get(0, "ItocOffset")
        self.gtoc_offset = u.get(0, "GtocOffset")
        self.content_offset = u.get(0, "ContentOffset")
        self.files = u.get(0, "Files")
        self.align = u.get(0, "Align") or ALIGN

    def _read_toc(self, f):
        if self.toc_offset in (None, NO_OFFSET):
            raise ValueError("This CPK has no TOC (ITOC only); this tool does not support it")
        toc = self._read_section(f, self.toc_offset, b"TOC ")
        self.sections["TOC"] = toc
        for name, off in (("ITOC", self.itoc_offset), ("ETOC", self.etoc_offset),
                          ("GTOC", self.gtoc_offset)):
            if off not in (None, NO_OFFSET):
                self.sections[name] = self._read_section(f, off, name.encode())

        # CriPakTools-style add_offset calculation
        ftoc = min(self.toc_offset, ALIGN)
        add = self.content_offset if self.content_offset < ftoc else ftoc

        u = toc.utf
        for i in range(u.num_rows):
            e = Entry(i)
            e.dirname = u.get(i, "DirName") or ""
            e.filename = u.get(i, "FileName") or ""
            e.path = (e.dirname + "/" + e.filename) if e.dirname else e.filename
            e.add_offset = add
            e.offset = u.get(i, "FileOffset") + add
            e.size = u.get(i, "FileSize")
            e.extract_size = u.get(i, "ExtractSize")
            e.id = u.get(i, "ID")
            self.entries.append(e)

    def _compute_slots(self):
        """Available space for each entry extends to the next occupied position."""
        marks = set()
        for e in self.entries:
            marks.add(e.offset)
        for name in ("TOC", "ITOC", "ETOC", "GTOC"):
            s = self.sections.get(name)
            if s is not None:
                marks.add(s.offset)
        marks.add(self.file_size)
        ordered = sorted(marks)
        import bisect
        for e in self.entries:
            j = bisect.bisect_right(ordered, e.offset)
            e.slot_end = ordered[j] if j < len(ordered) else self.file_size


def _fmt(n):
    return "0x%X (%s)" % (n, "{:,}".format(n))


def _align_up(v, a=ALIGN):
    return (v + a - 1) // a * a


def _merge(regions):
    """Merge [(start,end)] regions into a sorted, non-overlapping list."""
    out = []
    for s, e in sorted(regions):
        if e <= s:
            continue
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def _take(free, i, start, need):
    """Cut [start, start+take) from free[i] and return start."""
    s, e = free[i]
    take = min(_align_up(need), e - start)
    left = []
    if start > s:
        left.append((s, start))
    if start + take < e:
        left.append((start + take, e))
    free[i:i + 1] = left
    return start


def _alloc_at(free, start, need):
    """Allocate at a fixed position, used for in-place writes so repeated patches do not grow the file."""
    for i, (s, e) in enumerate(free):
        if s <= start and start + need <= e:
            return _take(free, i, start, need)
    return None


def _alloc_best(free, need):
    """Best-fit allocation. Returns the start position, or None."""
    best, best_len = -1, None
    for i, (s, e) in enumerate(free):
        ln = e - s
        if ln >= need and (best_len is None or ln < best_len):
            best, best_len = i, ln
    if best < 0:
        return None
    return _take(free, best, free[best][0], need)


class Change:
    __slots__ = ("entry", "local", "size", "offset", "kind")

    def __init__(self, entry, local, size):
        self.entry = entry
        self.local = local
        self.size = size
        self.offset = None
        self.kind = ""          # inplace / moved / appended


CHUNK = 1 << 20


def collect_inputs(root):
    """Walk the input folder and return {CPK-relative path: local full path}."""
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            out[rel] = full
    return out


def match_entries(cpk, inputs):
    by_path = {e.path: e for e in cpk.entries}
    by_lower = {}
    by_name = {}
    for e in cpk.entries:
        by_lower.setdefault(e.path.lower(), e)
        by_name.setdefault(e.filename.lower(), []).append(e)

    matched, missing = [], []
    for rel in sorted(inputs):
        e = by_path.get(rel) or by_lower.get(rel.lower())
        if e is None:
            cands = by_name.get(os.path.basename(rel).lower(), [])
            if len(cands) == 1:          # match by filename only when it is unique
                e = cands[0]
        if e is None:
            missing.append(rel)
        else:
            matched.append((e, inputs[rel]))
    return matched, missing


def _same_bytes(f, offset, size, local):
    """Compare existing CPK data with a local file."""
    f.seek(offset)
    with open(local, "rb") as g:
        left = size
        while left > 0:
            n = min(CHUNK, left)
            if f.read(n) != g.read(n):
                return False
            left -= n
    return True


def patch_cpk(cpk, matched, dry_run=False, log=print):
    """Apply an incremental in-place patch. Returns a statistics dict."""
    stats = dict(unchanged=0, inplace=0, moved=0, appended=0, written=0)
    changes = []

    with open(cpk.path, "rb") as f:
        for e, local in matched:
            size = os.path.getsize(local)
            if e.size == size and e.extract_size == size and _same_bytes(f, e.offset, size, local):
                stats["unchanged"] += 1
                continue
            changes.append(Change(e, local, size))

    if not changes:
        log("All files are already up to date; nothing to change.")
        return stats

    # 1) Available space = the original regions occupied by replaced files, including padding
    free = _merge([(c.entry.offset, c.entry.slot_end) for c in changes])

    # 2) Try to write back to the original position first
    todo = []
    for c in changes:
        if c.size <= c.entry.slot and _alloc_at(free, c.entry.offset, c.size) is not None:
            c.offset, c.kind = c.entry.offset, "inplace"
        else:
            todo.append(c)

    # 3) Move the remaining files to other free space, largest first, using best-fit
    rest = []
    for c in sorted(todo, key=lambda x: -x.size):
        pos = _alloc_best(free, c.size)
        if pos is None:
            rest.append(c)
        else:
            c.offset, c.kind = pos, "moved"

    # 4) Append anything that still does not fit at the end of the content area
    tail = cpk.etoc_offset if cpk.etoc_offset not in (None, NO_OFFSET) else _align_up(cpk.file_size)
    pos = tail
    for c in rest:
        c.offset, c.kind = pos, "appended"
        pos = _align_up(pos + c.size)
    new_etoc = pos

    for c in changes:
        stats[c.kind] += 1
        stats["written"] += c.size
    stats["new_etoc"] = new_etoc
    stats["old_etoc"] = tail
    return _apply(cpk, changes, new_etoc, stats, dry_run, log)


def _apply(cpk, changes, new_etoc, stats, dry_run, log):
    toc = cpk.sections["TOC"]
    etoc = cpk.sections.get("ETOC")
    hdr = cpk.sections["CPK"]
    move_etoc = etoc is not None and new_etoc != etoc.offset

    for c in changes:
        log("  [%-8s] %-44s %8d -> %8d bytes @0x%X"
            % (c.kind, c.entry.path, c.entry.size, c.size, c.offset))

    if dry_run:
        log("--- dry-run; no data written ---")
        return stats

    with open(cpk.path, "r+b") as f:
        # 1) File data
        for c in changes:
            f.seek(c.offset)
            with open(c.local, "rb") as g:
                left = c.size
                while left > 0:
                    buf = g.read(min(CHUNK, left))
                    if not buf:
                        raise IOError("Unexpected end of file while reading %s" % c.local)
                    f.write(buf)
                    left -= len(buf)
            pad = _align_up(c.offset + c.size) - (c.offset + c.size)
            if pad:
                f.write(b"\x00" * pad)

        # 2) Update TOC fields in place; widths do not change, so the TOC size stays the same
        u = toc.utf
        for c in changes:
            i = c.entry.index
            poke(toc.packet, u.cell(i, "FileOffset"), c.offset - c.entry.add_offset)
            poke(toc.packet, u.cell(i, "FileSize"), c.size)
            if u.cell(i, "ExtractSize") is not None:
                poke(toc.packet, u.cell(i, "ExtractSize"), c.size)
            c.entry.offset, c.entry.size, c.entry.extract_size = c.offset, c.size, c.size
        toc.write_back(f)

        # 3) If the content area grew, move ETOC to the new end and update the header
        end = cpk.file_size
        if move_etoc:
            end = etoc.write_full(f, new_etoc)
            poke(hdr.packet, hdr.utf.cell(0, "EtocOffset"), new_etoc)
            cs = hdr.utf.cell(0, "ContentSize")
            if cs is not None:
                poke(hdr.packet, cs, new_etoc - cpk.content_offset)
            hdr.write_back(f)
            log("ETOC moved to 0x%X; ContentSize updated to %s" % (new_etoc, _fmt(new_etoc - cpk.content_offset)))
        elif etoc is None:
            end = max(cpk.file_size, new_etoc)
        f.flush()
        f.truncate(end)
    stats["file_size"] = end
    return stats


def verify(cpk_path, matched, log=print):
    """Reopen the CPK and verify every patched file."""
    cpk = Cpk(cpk_path)
    by_path = {e.path: e for e in cpk.entries}
    bad = []
    with open(cpk_path, "rb") as f:
        for e0, local in matched:
            e = by_path.get(e0.path)
            size = os.path.getsize(local)
            if e is None or e.size != size or e.extract_size != size:
                bad.append((e0.path, "TOC size mismatch"))
                continue
            if e.offset + size > cpk.file_size:
                bad.append((e0.path, "offset beyond end of file"))
                continue
            if not _same_bytes(f, e.offset, size, local):
                bad.append((e0.path, "content mismatch"))
    if bad:
        log("!!! Verification failed for %d entries:" % len(bad))
        for p, why in bad[:20]:
            log("    %s : %s" % (p, why))
    else:
        log("Verification passed: %d files match their sources." % len(matched))
    return len(bad)







def cmd_info(args):
    t0 = time.time()
    cpk = Cpk(args.cpk)
    print("File         : %s" % cpk.path)
    print("Size         : %s" % _fmt(cpk.file_size))
    print("Files field  : %s" % cpk.files)
    print("TOC entries  : %s" % len(cpk.entries))
    print("Align        : 0x%X" % cpk.align)
    print("ContentOffset: %s" % _fmt(cpk.content_offset))
    for name in ("CPK", "TOC", "ITOC", "ETOC", "GTOC"):
        s = cpk.sections.get(name)
        if s is None:
            print("%-5s        : none" % name)
        else:
            print("%-5s        : @%s  packet=%s  encrypted=%s"
                  % (name, _fmt(s.offset), _fmt(len(s.packet)), s.encrypted))
    comp = [e for e in cpk.entries if e.extract_size and e.size != e.extract_size]
    print("Compressed (CRILAYLA) entries: %d / %d" % (len(comp), len(cpk.entries)))
    if cpk.entries:
        last = max(cpk.entries, key=lambda e: e.offset)
        print("Last entry   : %s @%s size=%s slot=%s"
              % (last.path, _fmt(last.offset), _fmt(last.size), _fmt(last.slot)))
        free = sum(e.slot - e.size for e in cpk.entries)
        print("Total existing padding space: %s" % _fmt(free))
    print("(Parsed in %.2fs)" % (time.time() - t0))


def cmd_list(args):
    cpk = Cpk(args.cpk)
    kw = (args.filter or "").lower()
    n = 0
    for e in cpk.entries:
        if kw and kw not in e.path.lower():
            continue
        n += 1
        print("%-46s off=0x%-10X size=%-10d ext=%-10s slot=%d"
              % (e.path, e.offset, e.size, e.extract_size, e.slot))
    print("--- %d entries ---" % n)


def cmd_patch(args):
    t0 = time.time()
    src = args.cpk
    target = args.output or src

    if target != src:
        if not args.dry_run:
            print("Copying %s -> %s ..." % (src, target))
            shutil.copyfile(src, target)
        else:
            target = src
    elif args.backup and not args.dry_run:
        bak = src + ".bak"
        if os.path.exists(bak):
            print("Backup already exists, skipping: %s" % bak)
        else:
            print("Backing up -> %s ..." % bak)
            shutil.copyfile(src, bak)

    cpk = Cpk(target)
    inputs = collect_inputs(args.input)
    if not inputs:
        print("No files found in the input folder: %s" % args.input)
        return 1
    matched, missing = match_entries(cpk, inputs)
    print("Input files: %d; matched TOC entries: %d" % (len(inputs), len(matched)))
    if missing:
        print("!! These files have no matching CPK entries and will be skipped:")
        for m in missing[:30]:
            print("    " + m)
        if len(missing) > 30:
            print("    ... %d more" % (len(missing) - 30))
        if args.strict:
            print("--strict: aborting.")
            return 2

    stats = patch_cpk(cpk, matched, dry_run=args.dry_run, log=print)
    print("-" * 60)
    print("Unchanged %d | in-place %d | moved %d | appended %d"
          % (stats["unchanged"], stats["inplace"], stats["moved"], stats["appended"]))
    print("Data written: %s" % _fmt(stats["written"]))
    if "file_size" in stats:
        print("CPK size: %s -> %s" % (_fmt(cpk.file_size), _fmt(stats["file_size"])))
    print("Elapsed: %.1fs" % (time.time() - t0))

    if args.dry_run or not matched:
        return 0
    if args.no_verify:
        return 0
    print("-" * 60)
    return 1 if verify(target, matched) else 0


def build_parser():
    p = argparse.ArgumentParser(description="CRI CPK in-place incremental archive patcher")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("info", help="Show CPK structure information")
    pi.add_argument("-p", "--cpk", required=True)
    pi.set_defaults(func=cmd_info)

    pl = sub.add_parser("list", help="List files in the TOC")
    pl.add_argument("-p", "--cpk", required=True)
    pl.add_argument("-f", "--filter", default="")
    pl.set_defaults(func=cmd_list)

    pp = sub.add_parser("patch", help="Incrementally replace CPK contents in place")
    pp.add_argument("-p", "--cpk", required=True, help="CPK file to modify")
    pp.add_argument("-i", "--input", required=True,
                    help="Folder containing replacement files; relative paths match CPK paths")
    pp.add_argument("-o", "--output", default="", help="Save to a new file (default: modify the original)")
    pp.add_argument("--backup", action="store_true", help="Create a .bak backup before modifying the original")
    pp.add_argument("--dry-run", action="store_true", help="Show the plan without writing")
    pp.add_argument("--strict", action="store_true", help="Abort if any input file cannot be matched")
    pp.add_argument("--no-verify", action="store_true", help="Skip post-patch verification")
    pp.set_defaults(func=cmd_patch)

    return p



def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
