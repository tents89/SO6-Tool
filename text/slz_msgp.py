#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Star Ocean: The Divine Force -- message_*.bin tool.

Container ("SLZ"):
  The whole file is XOR-obfuscated with a 4-byte key.
  key = file[0:4] XOR b"SLZ\x07"   (the plaintext magic is 'S','L','Z',0x07)

  Header (0x30 bytes, after de-XOR, all little endian):
    0x00 u8[4] 'S' 'L' 'Z' 0x07
    0x04 u32   0x00260100      constant in every observed file
    0x08 u32   payload_size    == filesize - 0x30 (sometimes -0x32, see probe)
    0x0C u32   0
    0x10 u32   uncompressed_size
    0x14 u32   0
    0x18 u32   0
    0x1C u32   data_offset     == 0x30
    0x20 u32   0x00014000      constant in every observed file
    0x24 u32   0
    0x28 u32   0
    0x2C u32   0

  Payload at 0x30: a chain of chunks, each   u16 frame_len | zstd frame
  Every chunk inflates to 0x10000 bytes (the last one to the remainder).

Payload content: a FlatBuffers buffer with file_identifier "MSGP".
"""
import argparse
import glob
import json
import os
import struct
import sys

import zstandard as zstd

VT_META = 2


class Builder:
    def __init__(self, size=4096):
        self.b = bytearray(size)
        self.head = size
        self.minalign = 1
        self.vtables = []
        self.vtable = None
        self.object_end = 0

    def offset(self):
        return len(self.b) - self.head

    def _grow(self):
        old = len(self.b)
        nb = bytearray(old * 2)
        nb[old:] = self.b
        self.head += old
        self.b = nb

    def pad(self, n):
        for _ in range(n):
            self.head -= 1
            self.b[self.head] = 0

    def prep(self, size, additional):
        if size > self.minalign:
            self.minalign = size
        align = ((~(self.offset() + additional)) + 1) & (size - 1)
        while self.head < align + size + additional:
            self._grow()
        self.pad(align)

    def place(self, fmt, size, value):
        self.head -= size
        struct.pack_into(fmt, self.b, self.head, value)

    def put_u8(self, v):
        self.prep(1, 0)
        self.place("<B", 1, v)

    def put_u16(self, v):
        self.prep(2, 0)
        self.place("<H", 2, v)

    def put_u32(self, v):
        self.prep(4, 0)
        self.place("<I", 4, v)

    def put_u64(self, v):
        self.prep(8, 0)
        self.place("<Q", 8, v)

    def put_f32(self, v):
        self.prep(4, 0)
        self.place("<f", 4, v)

    def put_uoffset(self, target):
        self.prep(4, 0)
        self.place("<I", 4, self.offset() - target + 4)

    def create_string(self, s):
        data = s.encode("utf-8")
        self.prep(4, len(data) + 1)
        self.pad(1)
        self.head -= len(data)
        self.b[self.head:self.head + len(data)] = data
        self.put_u32(len(data))
        return self.offset()

    def start_table(self, nslots):
        self.vtable = [0] * nslots
        self.object_end = self.offset()

    def _slot(self, n):
        self.vtable[n] = self.offset()

    def add_u8(self, slot, v):
        self.put_u8(v)
        self._slot(slot)

    def add_u64(self, slot, v):
        self.put_u64(v)
        self._slot(slot)

    def add_f32(self, slot, v):
        self.put_f32(v)
        self._slot(slot)

    def add_offset(self, slot, target):
        self.put_uoffset(target)
        self._slot(slot)

    def end_table(self):
        self.put_u32(0)
        obj = self.offset()
        while self.vtable and self.vtable[-1] == 0:
            self.vtable.pop()

        reuse = 0
        for vt in reversed(self.vtables):
            start = len(self.b) - vt
            vt_len = struct.unpack_from("<H", self.b, start)[0]
            body = self.b[start + VT_META * 2:start + vt_len]
            if self._vtable_equal(obj, body):
                reuse = vt
                break

        if reuse == 0:
            for e in reversed(self.vtable):
                self.put_u16(obj - e if e else 0)
            self.put_u16(obj - self.object_end)
            self.put_u16((len(self.vtable) + VT_META) * 2)
            struct.pack_into("<i", self.b, len(self.b) - obj, self.offset() - obj)
            self.vtables.append(self.offset())
        else:
            self.head = len(self.b) - obj
            struct.pack_into("<i", self.b, self.head, reuse - obj)
        self.vtable = None
        return obj

    def _vtable_equal(self, obj, body):
        if len(body) != len(self.vtable) * 2:
            return False
        for i, e in enumerate(self.vtable):
            got = struct.unpack_from("<H", body, i * 2)[0]
            want = (obj - e) if e else 0
            if got != want:
                return False
        return True

    def start_vector(self, elem_size, count, alignment=4):
        self.prep(4, elem_size * count)
        self.prep(alignment, elem_size * count)
        return self.offset()

    def end_vector(self, count):
        self.put_u32(count)
        return self.offset()

    def finish(self, root, file_identifier=None):
        prep = 4 + (4 if file_identifier else 0)
        self.prep(self.minalign, prep)
        if file_identifier:
            assert len(file_identifier) == 4
            self.prep(4, 4)
            for c in reversed(file_identifier):
                self.put_u8(c)
        self.put_uoffset(root)
        return bytes(self.b[self.head:])

SLZ_MAGIC = b"SLZ\x07"
HDR_SIZE = 0x30
CHUNK_UNC = 0x10000
MSGP_ID = b"MSGP"


# --------------------------------------------------------------------------
# container
# --------------------------------------------------------------------------
def xor4(data: bytes, key: bytes) -> bytes:
    pad = (key * (len(data) // 4 + 2))[: len(data)]
    return bytes(a ^ b for a, b in zip(data, pad))


def slz_key(raw: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(raw[:4], SLZ_MAGIC))


def slz_info(raw: bytes) -> dict:
    key = slz_key(raw)
    hdr = xor4(raw[:HDR_SIZE], key)
    f = struct.unpack_from("<12I", hdr, 0)
    return {
        "key": key,
        "magic": hdr[:4],
        "f04": f[1],
        "payload_size": f[2],
        "f0c": f[3],
        "unc_size": f[4],
        "f14": f[5],
        "f18": f[6],
        "data_off": f[7],
        "f20": f[8],
        "f24": f[9],
        "f28": f[10],
        "f2c": f[11],
    }


def slz_unpack(raw: bytes) -> tuple:
    """returns (decompressed_bytes, info, chunks) ; chunks = [(comp, unc), ...]"""
    info = slz_info(raw)
    if info["magic"] != SLZ_MAGIC:
        raise ValueError("not an SLZ file")
    dec = xor4(raw, info["key"])
    dctx = zstd.ZstdDecompressor()
    pos = info["data_off"]
    end = pos + info["payload_size"]
    out = bytearray()
    chunks = []
    while pos + 2 <= end:
        n = struct.unpack_from("<H", dec, pos)[0]
        pos += 2
        if n == 0:
            break
        frame = dec[pos : pos + n]
        pos += n
        piece = dctx.decompress(frame)
        chunks.append((n, len(piece)))
        out += piece
    if len(out) != info["unc_size"]:
        raise ValueError("size mismatch: got %d, header says %d" % (len(out), info["unc_size"]))
    return bytes(out), info, chunks


def slz_pack(data: bytes, key: bytes = b"\0\0\0\0", level: int = 19) -> bytes:
    cctx = zstd.ZstdCompressor(level=level, write_content_size=True, write_checksum=False)
    payload = bytearray()
    step = CHUNK_UNC
    pos = 0
    while pos < len(data):
        piece = data[pos : pos + step]
        frame = cctx.compress(piece)
        while len(frame) > 0xFFFF:          # must fit the u16 length prefix
            step //= 2
            piece = data[pos : pos + step]
            frame = cctx.compress(piece)
        payload += struct.pack("<H", len(frame)) + frame
        pos += len(piece)
    hdr = bytearray(HDR_SIZE)
    hdr[0:4] = SLZ_MAGIC
    struct.pack_into("<I", hdr, 0x04, 0x00260100)
    struct.pack_into("<I", hdr, 0x08, len(payload))
    struct.pack_into("<I", hdr, 0x10, len(data))
    struct.pack_into("<I", hdr, 0x1C, HDR_SIZE)
    struct.pack_into("<I", hdr, 0x20, 0x00014000)
    blob = bytes(hdr) + bytes(payload)
    blob += bytes(1) * (-len(blob) % 4)   # originals are padded out to a 4-byte boundary
    return xor4(blob, key)


# --------------------------------------------------------------------------
# minimal FlatBuffers reader
# --------------------------------------------------------------------------
class FB:
    def __init__(self, buf: bytes):
        self.b = buf

    def u8(self, o):
        return self.b[o]

    def u16(self, o):
        return struct.unpack_from("<H", self.b, o)[0]

    def i32(self, o):
        return struct.unpack_from("<i", self.b, o)[0]

    def u32(self, o):
        return struct.unpack_from("<I", self.b, o)[0]

    def u64(self, o):
        return struct.unpack_from("<Q", self.b, o)[0]

    def root(self):
        return self.u32(0)

    def file_id(self):
        return self.b[4:8]

    def fields(self, tbl):
        """-> ({slot: absolute field offset}, table_size)"""
        vt = tbl - self.i32(tbl)
        vt_size = self.u16(vt)
        tbl_size = self.u16(vt + 2)
        out = {}
        for i in range((vt_size - 4) // 2):
            off = self.u16(vt + 4 + 2 * i)
            if off:
                out[i] = tbl + off
        return out, tbl_size

    def deref(self, off):
        return off + self.u32(off)

    def string(self, off):
        p = self.deref(off)
        n = self.u32(p)
        return self.b[p + 4 : p + 4 + n]

    def vector(self, off):
        p = self.deref(off)
        return p + 4, self.u32(p)

    def is_string(self, off):
        try:
            rel = self.u32(off)
            p = off + rel
            if rel == 0 or p + 4 > len(self.b):
                return False
            n = self.u32(p)
            if p + 4 + n + 1 > len(self.b):
                return False
            if self.b[p + 4 + n] != 0:
                return False
            self.b[p + 4 : p + 4 + n].decode("utf-8")
            return True
        except Exception:
            return False


def msgp_tables(buf: bytes):
    """-> (FB, [message table offsets])"""
    fb = FB(buf)
    if fb.file_id() != MSGP_ID:
        raise ValueError("file_identifier is %r, expected %r" % (fb.file_id(), MSGP_ID))
    rootf, _ = fb.fields(fb.root())
    if 0 not in rootf:
        return fb, []
    base, count = fb.vector(rootf[0])
    return fb, [fb.deref(base + 4 * i) for i in range(count)]


def widths(fields, tbl_size, tbl):
    """infer each field's byte width from the layout of the table"""
    items = sorted((off - tbl, slot) for slot, off in fields.items())
    res = {}
    for i, (rel, slot) in enumerate(items):
        nxt = items[i + 1][0] if i + 1 < len(items) else tbl_size
        res[slot] = nxt - rel
    return res


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def bins(paths):
    out = []
    for p in paths:
        if os.path.isdir(p):
            out += [os.path.join(p, f) for f in sorted(os.listdir(p)) if f.lower().endswith(".bin")]
        else:
            out.append(p)
    return out


def cmd_probe(args):
    consts = {}
    bad = []
    print("%-34s %8s %8s %9s %6s %5s %s" % ("file", "size", "payload", "unc", "chunks", "tail", "key"))
    for p in bins(args.paths):
        raw = open(p, "rb").read()
        try:
            data, info, chunks = slz_unpack(raw)
        except Exception as e:
            bad.append((p, str(e)))
            continue
        tail = len(raw) - HDR_SIZE - info["payload_size"]
        print("%-34s %8d %8d %9d %6d %5d %s"
              % (os.path.basename(p), len(raw), info["payload_size"], info["unc_size"],
                 len(chunks), tail, info["key"].hex()))
        for k in ("f04", "f0c", "f14", "f18", "data_off", "f20", "f24", "f28", "f2c"):
            consts.setdefault(k, set()).add(info[k])
        consts.setdefault("chunk_unc", set()).update(u for _, u in chunks[:-1])
        consts.setdefault("tail", set()).add(tail)
        consts.setdefault("file_id", set()).add(data[4:8])
    print("\n-- constant header fields across all files --")
    for k, v in consts.items():
        vals = sorted(v, key=lambda x: (isinstance(x, bytes), x))
        print("  %-10s %s" % (k, ", ".join(repr(x) if isinstance(x, bytes) else hex(x) for x in vals[:8])))
    if bad:
        print("\n-- failures --")
        for p, e in bad:
            print("  %s: %s" % (p, e))
    else:
        print("\nall %d files decoded and size-verified" % len(bins(args.paths)))


def cmd_discover(args):
    slots = {}
    nmsg = 0
    nfile = 0
    for p in bins(args.paths):
        data, _, _ = slz_unpack(open(p, "rb").read())
        fb, tables = msgp_tables(data)
        nfile += 1
        for t in tables:
            nmsg += 1
            f, tsz = fb.fields(t)
            w = widths(f, tsz, t)
            for slot, off in f.items():
                s = slots.setdefault(slot, {"n": 0, "w": set(), "str": 0, "vals": set(), "sample": None})
                s["n"] += 1
                s["w"].add(w[slot])
                if w[slot] >= 4 and fb.is_string(off):
                    s["str"] += 1
                    if s["sample"] is None:
                        txt = fb.string(off).decode("utf-8")
                        if txt:
                            s["sample"] = txt[:40]
                elif w[slot] == 1:
                    s["vals"].add(fb.u8(off))
    print("%d files, %d message tables\n" % (nfile, nmsg))
    print("%-5s %8s %8s %8s  %s" % ("slot", "present", "widths", "string?", "sample / byte values"))
    for slot in sorted(slots):
        s = slots[slot]
        extra = s["sample"] if s["str"] else ("bytes " + ",".join(str(x) for x in sorted(s["vals"])[:16]))
        print("%-5d %8d %8s %8d  %s"
              % (slot, s["n"], ",".join(str(x) for x in sorted(s["w"])), s["str"], extra))


def cmd_msgp(args):
    """Write the decompressed FlatBuffers payload as a raw .msgp file."""
    for p in bins(args.paths):
        data, info, chunks = slz_unpack(open(p, "rb").read())
        stem = os.path.splitext(os.path.basename(p))[0] + ".msgp"
        if args.out:
            os.makedirs(args.out, exist_ok=True)
            out = os.path.join(args.out, stem)
        else:
            out = os.path.join(os.path.dirname(p), stem)
        with open(out, "wb") as fh:
            fh.write(data)
        print("%s -> %s  (%d bytes, %d chunks, key %s)"
              % (os.path.basename(p), out, len(data), len(chunks), info["key"].hex()))


# Backward-compatible implementation name for callers importing the module.
cmd_unpack = cmd_msgp


def cmd_pack(args):
    data = open(args.src, "rb").read()
    key = b"\0\0\0\0"
    if args.like:
        key = slz_key(open(args.like, "rb").read())
    elif args.key:
        key = bytes.fromhex(args.key)
    out = slz_pack(data, key, args.level)
    with open(args.dst, "wb") as fh:
        fh.write(out)
    back, _, _ = slz_unpack(out)
    print("%s -> %s  (%d -> %d bytes, roundtrip %s)"
          % (args.src, args.dst, len(data), len(out), "OK" if back == data else "FAILED"))


# --------------------------------------------------------------------------
# MSGP schema (recovered from the 116 zh-tw files: 40496 message tables)
#   slots 1..6 are present on every message, the rest are optional
# --------------------------------------------------------------------------
SLOTS = [
    (0, "id", "u64"),          # 64-bit hash of "key"; the vector is sorted by it
    (1, "key", "str"),         # identifier, e.g. ITEM_10090_NAME / vo_talk_180_480_x_d0112_00
    (2, "s2", "str"),          # speaker label, japanese, dev-facing
    (3, "s3", "str"),          # ditto
    (4, "s4", "str"),
    (5, "text", "str"),        # <-- the localised string shown in game
    (6, "s6", "str"),
    (7, "u7", "u8"),
    (8, "u8", "u8"),
    (9, "u9", "u8"),
    (10, "u10", "u8"),
    (11, "u11", "u8"),
    (12, "s12", "str"),
    (13, "u13", "u8"),
    (14, "name_key", "str"),   # speaker name key, resolved in message_chara_name
    (15, "u15", "u8"),
    (16, "f16", "f32"),        # only in event files: 0.0 / 100.0 / 1000.0 ...
    (17, "u17", "u8"),
    (18, "u18", "u8"),
    (19, "u19", "u8"),
]
SLOT_NAME = {s: n for s, n, _ in SLOTS}
SLOT_TYPE = {s: t for s, _, t in SLOTS}


def read_message(fb, tbl):
    f, _ = fb.fields(tbl)
    row = {}
    for slot in sorted(f):
        off = f[slot]
        t = SLOT_TYPE.get(slot)
        if t == "str":
            row[SLOT_NAME[slot]] = fb.string(off).decode("utf-8")
        elif t == "u8":
            row[SLOT_NAME[slot]] = fb.u8(off)
        elif t == "u64":
            row[SLOT_NAME[slot]] = "0x%016X" % fb.u64(off)
        elif t == "f32":
            row[SLOT_NAME[slot]] = struct.unpack_from("<f", fb.b, off)[0]
        else:
            row["slot%d" % slot] = fb.u32(off)
    return row


# --------------------------------------------------------------------------
# TSV worklist: file / key / name_key / text
#   The game's own line break is a *literal* backslash-n inside the string, so
#   backslash escapes are unusable here -- they would double every one of the
#   12382 markers translators need to copy verbatim.  Real control characters
#   (only one string in the whole zh-tw corpus has one) use <LF>/<CR>/<TAB>
#   instead; `dump` refuses to write a row where that would be ambiguous.
# --------------------------------------------------------------------------
TSV_HEADER = "file\tkey\tname_key\ttext\n"
TSV_ESC = ((chr(9), "<TAB>"), (chr(13), "<CR>"), (chr(10), "<LF>"))


def tsv_encode(s, where=""):
    for raw, tok in TSV_ESC:
        if tok in s:
            raise ValueError("%s contains the escape token %s verbatim, cannot "
                             "round-trip through TSV" % (where or repr(s), tok))
    for raw, tok in TSV_ESC:
        s = s.replace(raw, tok)
    return s


def tsv_decode(s):
    for raw, tok in TSV_ESC:
        s = s.replace(tok, raw)
    return s


def tsv_rows(fh, stem, messages):
    """Append the translatable rows of one file, return how many."""
    n = 0
    for r in messages:
        txt = r.get("text", "")
        if not txt:
            continue
        where = "%s/%s" % (stem, r.get("key", ""))
        fh.write("%s\t%s\t%s\t%s\n" % (stem, r.get("key", ""), r.get("name_key", ""),
                                       tsv_encode(txt, where)))
        n += 1
    return n


def read_tsv(path):
    """-> ({(file, key, name_key): text}, row_count).

    ``name_key`` is part of the identity because keys are only unique within
    their speaker context in some message files.  An empty name_key is a
    deliberate value for messages that do not have that optional field.
    """
    out = {}
    n = 0
    with open(path, encoding="utf-8") as fh:
        head = fh.readline().rstrip("\n").split("\t")
        if head[:4] != ["file", "key", "name_key", "text"]:
            raise ValueError("%s: unexpected header %r" % (path, head))
        for lineno, line in enumerate(fh, 2):
            line = line.rstrip("\n")
            if not line:
                continue
            col = line.split("\t")
            if len(col) != 4:
                raise ValueError("%s:%d: %d columns, expected 4" % (path, lineno, len(col)))
            f, k, nk, txt = col
            identity = (f, k, nk)
            if identity in out:
                raise ValueError("%s:%d: duplicate row for %s/%s" % (path, lineno, f, k))
            out[identity] = tsv_decode(txt)
            n += 1
    return out, n


def merge_tsv(doc, stem, rows, used=None, speaker_drift=None):
    """Apply the rows for *stem* to a dumped JSON document in memory.

    ``file``, ``key`` and ``name_key`` identify a message.  An empty
    ``name_key`` matches only a message where that optional field is absent or
    empty; it never adds an empty field to JSON.
    """
    changed = same = 0
    for message in doc["messages"]:
        key = message.get("key", "")
        name_key = message.get("name_key", "")
        row_key = (stem, key, name_key)
        row = rows.get(row_key)
        if row is None:
            continue
        if used is not None:
            used.add(row_key)

        text = row
        if text == message.get("text", ""):
            same += 1
        else:
            message["text"] = text
            changed += 1
    return changed, same


def cmd_dump(args):
    os.makedirs(args.out, exist_ok=True)
    # dump is the single extraction command; the worklist is generated by
    # default.  --no-tsv is available for JSON-only callers.
    tsv_path = None if args.no_tsv else (args.tsv or "text.tsv")
    tsv = open(tsv_path, "w", encoding="utf-8", newline="\n") if tsv_path else None
    if tsv:
        tsv.write(TSV_HEADER)
    total = ntext = 0
    try:
        for p in bins(args.paths):
            data, info, _ = slz_unpack(open(p, "rb").read())
            fb, tables = msgp_tables(data)
            stem = os.path.splitext(os.path.basename(p))[0]
            doc = {
                "source": os.path.basename(p),
                "xor_key": info["key"].hex(),
                "count": len(tables),
                "messages": [read_message(fb, t) for t in tables],
            }
            dst = os.path.join(args.out, stem + ".json")
            with open(dst, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(doc, fh, ensure_ascii=False, indent=1)
            if tsv:
                ntext += tsv_rows(tsv, stem, doc["messages"])
            total += len(tables)
            print("%-34s %6d entries -> %s" % (os.path.basename(p), len(tables), dst))
    finally:
        if tsv:
            tsv.close()
    print("\n%d entries dumped" % total)
    if tsv:
        print("%d translatable strings -> %s" % (ntext, tsv_path))


def cmd_apply(args):
    """Map an edited TSV back onto the JSON files."""
    rows, nrows = read_tsv(args.tsv)
    src = args.json
    dst = src if args.in_place else args.out
    if not dst:
        raise SystemExit("give -o OUTDIR, or --in-place to overwrite the JSON in place")
    if not args.in_place:
        os.makedirs(dst, exist_ok=True)

    used = set()
    changed = same = 0
    speaker_drift = []
    files_written = 0
    for p in sorted(glob.glob(os.path.join(src, "*.json"))):
        stem = os.path.splitext(os.path.basename(p))[0]
        with open(p, encoding="utf-8") as fh:
            doc = json.load(fh)
        hits, identical = merge_tsv(doc, stem, rows, used, speaker_drift)
        changed += hits
        same += identical
        if hits or not args.changed_only:
            out = os.path.join(dst, stem + ".json")
            with open(out, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(doc, fh, ensure_ascii=False, indent=1)
            files_written += 1
        if hits:
            print("%-34s %5d string(s) updated" % (stem + ".json", hits))

    missing = sorted(set(rows) - used)
    print("\n%d TSV row(s): %d changed, %d already identical, %d unmatched"
          % (nrows, changed, same, len(missing)))
    print("%d JSON file(s) written to %s" % (files_written, dst))
    for f, k, nk in missing[:10]:
        print("  unmatched: %s / %s / %s" % (f, k, nk or "<empty name_key>"))
    if len(missing) > 10:
        print("  ... and %d more" % (len(missing) - 10))
    for s in speaker_drift[:5]:
        print("  warning: " + s)
    if len(speaker_drift) > 5:
        print("  ... and %d more name_key warnings" % (len(speaker_drift) - 5))


# --------------------------------------------------------------------------
# writing: JSON -> FlatBuffers .msgp
# --------------------------------------------------------------------------
NSLOTS = max(s for s, _, _ in SLOTS) + 1
KNOWN = set(SLOT_NAME.values())


def _as_int(v):
    return int(v, 16) if isinstance(v, str) else v


def build_message(b, m):
    """Emit one Message table, return its offset.

    Strings have to be built before the table is opened.  Fields are added
    u64 -> f32 -> strings -> u8 because the builder fills the buffer
    backwards, and that order reproduces the field layout of the originals.
    """
    unknown = set(m) - KNOWN
    if unknown:
        raise ValueError("unknown field(s) %s in %r" % (sorted(unknown), m.get("key")))
    strs = {}
    for slot, name, t in SLOTS:
        if t == "str" and name in m:
            strs[slot] = b.create_string(m[name])
    b.start_table(NSLOTS)
    for slot, name, t in SLOTS:
        if t == "u64" and name in m:
            b.add_u64(slot, _as_int(m[name]))
    for slot, name, t in SLOTS:
        if t == "f32" and name in m:
            b.add_f32(slot, m[name])
    for slot, name, t in reversed(SLOTS):
        if t == "str" and name in m:
            b.add_offset(slot, strs[slot])
    for slot, name, t in reversed(SLOTS):
        if t == "u8" and name in m:
            b.add_u8(slot, m[name])
    return b.end_table()


def build_msgp(doc, size_hint=1 << 20):
    """JSON document (as produced by `dump`) -> MSGP FlatBuffers buffer."""
    msgs = doc["messages"]
    # the game binary-searches the vector, so it must stay sorted by id
    order = sorted(range(len(msgs)), key=lambda i: _as_int(msgs[i]["id"]))
    b = Builder(max(size_hint, 4096))
    offs = [build_message(b, msgs[i]) for i in order]
    b.start_vector(4, len(offs))
    for o in reversed(offs):
        b.put_uoffset(o)
    vec = b.end_vector(len(offs))
    b.start_table(1)
    b.add_offset(0, vec)
    root = b.end_table()
    return b.finish(root, MSGP_ID)


def resolve_build_inputs(args):
    """Return ``(json_inputs, tsv_path)`` for TSV-first and legacy syntax."""
    inputs = list(args.paths)
    tsv_path = args.tsv
    positional_tsv = [p for p in inputs
                      if os.path.splitext(p)[1].lower() == ".tsv"]
    if tsv_path is None and positional_tsv:
        if len(positional_tsv) > 1:
            raise SystemExit("build accepts only one translation TSV")
        tsv_path = positional_tsv[0]
        inputs.remove(tsv_path)
    if tsv_path and not inputs:
        inputs = [args.json]
    if not inputs:
        raise SystemExit("give a translation TSV, or JSON files/a directory")
    return inputs, tsv_path


def expand_json_inputs(inputs):
    paths = []
    for p in inputs:
        if os.path.isdir(p):
            paths += sorted(glob.glob(os.path.join(p, "*.json")))
        else:
            paths.append(p)
    return paths


def cmd_build(args):
    os.makedirs(args.out, exist_ok=True)
    inputs, tsv_path = resolve_build_inputs(args)
    paths = expand_json_inputs(inputs)

    rows = {}
    nrows = 0
    if tsv_path:
        rows, nrows = read_tsv(tsv_path)
    used = set()
    speaker_drift = []
    changed = same = 0

    total = 0
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            doc = json.load(fh)
        stem = os.path.splitext(os.path.basename(p))[0]
        if tsv_path:
            delta, identical = merge_tsv(doc, stem, rows, used, speaker_drift)
            changed += delta
            same += identical
        buf = build_msgp(doc, size_hint=1 << 20)
        if args.raw:
            dst = os.path.join(args.out, stem + ".msgp")
            blob = buf
        else:
            dst = os.path.join(args.out, stem + ".bin")
            key = bytes.fromhex(doc.get("xor_key") or "00000000")
            blob = slz_pack(buf, key, args.level)
        with open(dst, "wb") as fh:
            fh.write(blob)
        total += len(doc["messages"])
        print("%-34s %6d entries  msgp=%-8d -> %s" % (stem, len(doc["messages"]), len(buf), dst))
    print("\n%d entries built into %d file(s)" % (total, len(paths)))

    if tsv_path:
        missing = sorted(set(rows) - used)
        print("%d TSV row(s): %d changed, %d already identical, %d unmatched"
              % (nrows, changed, same, len(missing)))
        for f, k, nk in missing[:10]:
            print("  unmatched: %s / %s / %s" % (f, k, nk or "<empty name_key>"))
        if len(missing) > 10:
            print("  ... and %d more" % (len(missing) - 10))
        for warning in speaker_drift[:5]:
            print("  warning: " + warning)
        if len(speaker_drift) > 5:
            print("  ... and %d more name_key warnings" % (len(speaker_drift) - 5))


def verify_msgp(buf):
    """Structural check -- there is no official flatbuffers verifier here."""
    problems = []
    if len(buf) < 8:
        return ["too short"]
    if buf[4:8] != MSGP_ID:
        problems.append("file_identifier %r != MSGP" % buf[4:8])
    fb = FB(buf)
    tables = []
    try:
        rootv, _ = fb.fields(fb.root())
        vec = fb.deref(rootv[0])
        n = fb.u32(vec)
        tables = [fb.deref(vec + 4 + 4 * i) for i in range(n)]
    except Exception as e:
        return problems + ["cannot walk root vector: %s" % e]
    last = -1
    for i, t in enumerate(tables):
        if not (0 <= t < len(buf)):
            problems.append("entry %d: table offset %d out of range" % (i, t))
            continue
        try:
            f, _ = fb.fields(t)
        except Exception as e:
            problems.append("entry %d: bad vtable (%s)" % (i, e))
            continue
        for slot, off in f.items():
            ty = SLOT_TYPE.get(slot)
            if ty == "str":
                try:
                    s = fb.string(off)
                    s.decode("utf-8")
                except Exception as e:
                    problems.append("entry %d slot %d: bad string (%s)" % (i, slot, e))
        if 0 in f:
            v = fb.u64(f[0])
            if v < last:
                problems.append("entry %d: id 0x%016X breaks the ascending order" % (i, v))
            last = v
        else:
            problems.append("entry %d: no id" % i)
    return problems


def cmd_verify(args):
    bad = 0
    for p in bins(args.paths):
        raw = open(p, "rb").read()
        try:
            data, _, _ = slz_unpack(raw) if raw[0:4] != MSGP_ID[::-1] else (raw, None, None)
        except Exception:
            data = raw
        if data[4:8] != MSGP_ID:
            data = raw          # already a bare .msgp
        probs = verify_msgp(data)
        n = len(probs)
        bad += bool(n)
        print("%-34s %s" % (os.path.basename(p), "OK" if not n else "%d problem(s)" % n))
        for x in probs[:10]:
            print("    " + x)
    print("\n%s" % ("all clean" if not bad else "%d file(s) with problems" % bad))


def cmd_roundtrip(args):
    """original .bin -> JSON -> rebuilt .msgp -> JSON', assert JSON == JSON'."""
    ok = fail = 0
    o_tot = n_tot = 0
    for p in bins(args.paths):
        raw = open(p, "rb").read()
        data, info, _ = slz_unpack(raw)
        fb, tables = msgp_tables(data)
        doc = {"xor_key": info["key"].hex(), "messages": [read_message(fb, t) for t in tables]}
        want = sorted(doc["messages"], key=lambda m: _as_int(m["id"]))
        buf = build_msgp(doc)
        probs = verify_msgp(buf)
        fb2, t2 = msgp_tables(buf)
        got = [read_message(fb2, t) for t in t2]
        o_tot += len(data)
        n_tot += len(buf)
        if got == want and not probs:
            ok += 1
            note = "identical" if buf == data else "equal fields"
            print("%-34s %6d entries  %8d -> %-8d bytes  %s" %
                  (os.path.basename(p), len(tables), len(data), len(buf), note))
        else:
            fail += 1
            print("%-34s MISMATCH" % os.path.basename(p))
            for x in probs[:5]:
                print("    verify: " + x)
            for i, (a, c) in enumerate(zip(want, got)):
                if a != c:
                    print("    first diff at %d:\n      want %r\n      got  %r" % (i, a, c))
                    break
            if len(want) != len(got):
                print("    count %d -> %d" % (len(want), len(got)))
    print("\n%d ok, %d failed;  msgp bytes %d -> %d" % (ok, fail, o_tot, n_tot))

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("probe", help="validate SLZ containers, report header constants")
    p.add_argument("paths", nargs="+")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("discover", help="report FlatBuffers slot usage over a set of files")
    p.add_argument("paths", nargs="+")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("msgp", help="SLZ -> raw .msgp FlatBuffers (optional export)")
    p.add_argument("paths", nargs="+")
    p.add_argument("-o", "--out")
    p.set_defaults(func=cmd_msgp)

    p = sub.add_parser("unpack", help="alias for msgp")
    p.add_argument("paths", nargs="+")
    p.add_argument("-o", "--out")
    p.set_defaults(func=cmd_msgp)

    p = sub.add_parser("extract", help="SLZ .bin -> JSON files and one TSV worklist")
    p.add_argument("paths", nargs="+")
    p.add_argument("-o", "--out", default="json")
    p.add_argument("-t", "--tsv", help="translation worklist path (default: text.tsv)")
    p.add_argument("--no-tsv", action="store_true", help="do not write the TSV worklist")
    p.set_defaults(func=cmd_dump)

    p = sub.add_parser("dump", help="alias for extract")
    p.add_argument("paths", nargs="+")
    p.add_argument("-o", "--out", default="json")
    p.add_argument("-t", "--tsv", help="translation worklist path (default: text.tsv)")
    p.add_argument("--no-tsv", action="store_true", help="do not write the TSV worklist")
    p.set_defaults(func=cmd_dump)

    p = sub.add_parser("pack", help="raw .msgp -> SLZ .bin")
    p.add_argument("src")
    p.add_argument("dst")
    p.add_argument("--like", help="copy the XOR key from this original .bin")
    p.add_argument("--key", help="4-byte XOR key as hex")
    p.add_argument("--level", type=int, default=19)
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser("apply", help="edited TSV -> update the JSON files")
    p.add_argument("tsv")
    p.add_argument("-j", "--json", default="json", help="directory of JSON files to update")
    p.add_argument("-o", "--out", help="write the updated JSON here")
    p.add_argument("--in-place", action="store_true", help="overwrite -j instead")
    p.add_argument("--changed-only", action="store_true",
                   help="only write the JSON files that actually changed")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("build", help="TSV + JSON -> .bin (or .msgp with --raw)")
    p.add_argument("paths", nargs="*", help="JSON files/directories, or one translation TSV")
    p.add_argument("-o", "--out", default="built")
    p.add_argument("-t", "--tsv", help="edited translation TSV; merge it before building")
    p.add_argument("-j", "--json", default="json",
                   help="JSON directory when the TSV is given as the positional input")
    p.add_argument("--raw", action="store_true", help="emit raw .msgp instead of a packed .bin")
    p.add_argument("--level", type=int, default=19)
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("verify", help="structurally validate .bin/.msgp buffers")
    p.add_argument("paths", nargs="+")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("roundtrip", help="self-test: .bin -> JSON -> .msgp -> JSON, compare")
    p.add_argument("paths", nargs="+")
    p.set_defaults(func=cmd_roundtrip)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
