#!/usr/bin/env python3
from __future__ import annotations

import io
import struct
import sys
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Iterable

import zstandard as zstd
from PIL import Image, ImageTk

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError:
    DND_FILES = None
    TkinterDnD = None


ROOT = Path(__file__).resolve().parent

AIF_MAGIC = b" FIA"
AIF_DATA_OFFSET = 0x270
SLZ_MAGIC = b"SLZ\x07"
SLZ_HEADER_SIZE = 0x30
SLZ_CHUNK_SIZE = 0x10000
FORMAT_MAP = {
    16: ("DXT1", 4, 8),
    18: ("DXT3", 8, 16),
    20: ("DXT5", 8, 16),
}


@dataclass(frozen=True)
class AifInfo:
    source: Path
    source_size: int
    payload_size: int
    width: int
    height: int
    format_code: int
    fourcc: str
    bits_per_pixel: int
    block_bytes: int
    blocks_x: int
    blocks_y: int
    row_bytes: int
    pixel_bytes: int
    data_offset: int
    container: str
    slz_key: str | None
    chunks: int | None


def xor4(data: bytes, key: bytes) -> bytes:
    pad = (key * (len(data) // 4 + 2))[: len(data)]
    return bytes(a ^ b for a, b in zip(data, pad))


def slz_key(raw: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(raw[:4], SLZ_MAGIC))


def slz_unpack(raw: bytes) -> tuple[bytes, bytes, list[tuple[int, int]]]:
    """Return the payload, XOR key, and (compressed, uncompressed) chunk sizes."""
    key = slz_key(raw)
    decoded = xor4(raw, key)
    if decoded[:4] != SLZ_MAGIC:
        raise ValueError("not an SLZ file")

    fields = struct.unpack_from("<12I", decoded, 0)
    payload_size = fields[2]
    uncompressed_size = fields[4]
    data_offset = fields[7]
    if data_offset != SLZ_HEADER_SIZE:
        raise ValueError(f"unexpected SLZ data offset 0x{data_offset:X}")

    pos = data_offset
    end = pos + payload_size
    output = bytearray()
    chunks: list[tuple[int, int]] = []
    decompressor = zstd.ZstdDecompressor()
    while pos + 2 <= end:
        frame_size = struct.unpack_from("<H", decoded, pos)[0]
        pos += 2
        if frame_size == 0:
            break
        frame = decoded[pos : pos + frame_size]
        pos += frame_size
        piece = decompressor.decompress(frame)
        chunks.append((frame_size, len(piece)))
        output += piece

    if len(output) != uncompressed_size:
        raise ValueError(
            f"SLZ size mismatch: got {len(output)}, header says {uncompressed_size}"
        )
    return bytes(output), key, chunks


def slz_pack(data: bytes, key: bytes) -> bytes:
    compressor = zstd.ZstdCompressor(
        level=19, write_content_size=True, write_checksum=False
    )
    payload = bytearray()
    pos = 0
    step = SLZ_CHUNK_SIZE
    while pos < len(data):
        piece = data[pos : pos + step]
        frame = compressor.compress(piece)
        while len(frame) > 0xFFFF:
            step //= 2
            piece = data[pos : pos + step]
            frame = compressor.compress(piece)
        payload += struct.pack("<H", len(frame)) + frame
        pos += len(piece)

    header = bytearray(SLZ_HEADER_SIZE)
    header[:4] = SLZ_MAGIC
    struct.pack_into("<I", header, 0x04, 0x00260100)
    struct.pack_into("<I", header, 0x08, len(payload))
    struct.pack_into("<I", header, 0x10, len(data))
    struct.pack_into("<I", header, 0x1C, SLZ_HEADER_SIZE)
    struct.pack_into("<I", header, 0x20, 0x00014000)
    blob = bytes(header) + bytes(payload)
    blob += bytes(1) * (-len(blob) % 4)
    return xor4(blob, key)


def collect_aif_files(paths: Iterable[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_file() and path.suffix.lower() == ".aif":
            files.append(path)
        elif path.is_dir():
            files.extend(
                item
                for item in path.rglob("*")
                if item.is_file() and item.suffix.lower() == ".aif"
            )
    return sorted(set(files))


def _read_payload(path: Path) -> tuple[bytes, str, str | None, int | None]:
    raw = path.read_bytes()
    if raw[:4] == AIF_MAGIC:
        return raw, "raw AIF", None, None

    payload, key, chunks = slz_unpack(raw)
    return payload, "SLZ", key.hex(), len(chunks)


def parse_aif(path: Path) -> tuple[bytes, AifInfo]:
    payload, container, slz_key, chunks = _read_payload(path)
    if len(payload) < AIF_DATA_OFFSET or payload[:4] != AIF_MAGIC:
        raise ValueError("not an AIF payload")

    width, height = struct.unpack_from("<HH", payload, 0xB8)
    format_code = struct.unpack_from("<H", payload, 0xB0)[0]
    if format_code not in FORMAT_MAP:
        raise ValueError(f"unsupported AIF format code {format_code}")

    fourcc, expected_bpp, expected_block_bytes = FORMAT_MAP[format_code]
    bits_per_pixel = struct.unpack_from("<H", payload, 0xBE)[0]
    block_bytes = struct.unpack_from("<H", payload, 0xC0)[0]
    blocks_x = struct.unpack_from("<H", payload, 0xC2)[0]
    blocks_y = struct.unpack_from("<H", payload, 0xC4)[0]
    row_bytes = struct.unpack_from("<I", payload, 0xC8)[0]
    pixel_bytes = struct.unpack_from("<I", payload, 0xCC)[0]

    if bits_per_pixel != expected_bpp:
        raise ValueError(
            f"format code {format_code} expects {expected_bpp} bpp, got {bits_per_pixel}"
        )
    if block_bytes != expected_block_bytes:
        raise ValueError(
            f"format code {format_code} expects {expected_block_bytes}-byte blocks, "
            f"got {block_bytes}"
        )
    if row_bytes != blocks_x * block_bytes:
        raise ValueError(
            f"row size mismatch: header={row_bytes}, calculated={blocks_x * block_bytes}"
        )
    expected_size = blocks_x * blocks_y * block_bytes
    if pixel_bytes != expected_size:
        raise ValueError(
            f"pixel size mismatch: header={pixel_bytes}, calculated={expected_size}"
        )
    if len(payload) < AIF_DATA_OFFSET + pixel_bytes:
        raise ValueError("truncated AIF pixel data")

    info = AifInfo(
        source=path,
        source_size=path.stat().st_size,
        payload_size=len(payload),
        width=width,
        height=height,
        format_code=format_code,
        fourcc=fourcc,
        bits_per_pixel=bits_per_pixel,
        block_bytes=block_bytes,
        blocks_x=blocks_x,
        blocks_y=blocks_y,
        row_bytes=row_bytes,
        pixel_bytes=pixel_bytes,
        data_offset=AIF_DATA_OFFSET,
        container=container,
        slz_key=slz_key,
        chunks=chunks,
    )
    return payload, info


def _make_dds(info: AifInfo, pixel_data: bytes) -> bytes:
    flags = 0x00081007  # CAPS | HEIGHT | WIDTH | PIXELFORMAT | LINEARSIZE
    pixel_format = struct.pack(
        "<II4sIIIII",
        32,
        0x4,
        info.fourcc.encode("ascii"),
        0,
        0,
        0,
        0,
        0,
    )
    header = struct.pack(
        "<4s7I44s32s5I",
        b"DDS ",
        124,
        flags,
        info.height,
        info.width,
        info.pixel_bytes,
        0,
        1,
        b"\0" * 44,
        pixel_format,
        0x1000,
        0,
        0,
        0,
        0,
    )
    return header + pixel_data


def decode_aif(path: Path) -> tuple[Image.Image, AifInfo]:
    payload, info = parse_aif(path)
    pixel_data = payload[info.data_offset : info.data_offset + info.pixel_bytes]
    dds_data = _make_dds(info, pixel_data)
    image = Image.open(io.BytesIO(dds_data))
    image.load()
    return image, info


def load_aif_bundle(path: Path) -> tuple[Image.Image, AifInfo, bytes, bytes]:
    """Load an AIF as image, metadata, complete payload, and pixel block data."""
    payload, info = parse_aif(path)
    pixel_data = payload[info.data_offset : info.data_offset + info.pixel_bytes]
    dds_data = _make_dds(info, pixel_data)
    image = Image.open(io.BytesIO(dds_data))
    image.load()
    return image, info, payload, pixel_data


def encode_image_to_dxt(image: Image.Image, fourcc: str) -> bytes:
    """Encode an RGBA image to raw DXT1/DXT3/DXT5 block data."""
    if fourcc not in {"DXT1", "DXT3", "DXT5"}:
        raise ValueError(f"unsupported target format {fourcc}")
    if image.mode != "RGBA":
        image = image.convert("RGBA")

    buffer = io.BytesIO()
    image.save(buffer, format="DDS", pixel_format=fourcc)
    dds_data = buffer.getvalue()
    if len(dds_data) <= 128:
        raise ValueError("Pillow produced an empty DDS image")
    return dds_data[128:]


def read_matching_dds_blocks(path: Path, fourcc: str, expected_size: int) -> bytes | None:
    """Read raw DXT blocks from a DDS when its format already matches."""
    data = path.read_bytes()
    if len(data) < 128 or data[:4] != b"DDS ":
        return None
    if data[84:88] != fourcc.encode("ascii"):
        return None
    blocks = data[128 : 128 + expected_size]
    return blocks if len(blocks) == expected_size else None


DND_BASE = TkinterDnD.Tk if TkinterDnD is not None else tk.Tk


class AifViewer(DND_BASE):
    def __init__(self) -> None:
        super().__init__()
        self.title("AIF / SLZ Viewer")
        self.geometry("1250x780")
        self.minsize(900, 560)

        self.files: list[Path] = []
        self.filtered_files: list[Path] = []
        self.root_dir: Path | None = None
        self.tree_items: dict[str, Path] = {}
        self.full_image: Image.Image | None = None
        self.current_info: AifInfo | None = None
        self.current_path: Path | None = None
        self.current_payload: bytes | None = None
        self.current_pixel_data: bytes | None = None
        self.scale = 1.0
        self._photo: ImageTk.PhotoImage | None = None

        self._build_ui()
        self.bind("<Configure>", self._on_window_configure, add="+")
        self._setup_drag_and_drop()

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        toolbar = ttk.Frame(self, padding=(8, 6))
        toolbar.grid(row=0, column=0, sticky="ew")
        toolbar.columnconfigure(3, weight=1)

        ttk.Button(toolbar, text="Open File…", command=self.open_file).grid(
            row=0, column=0, padx=(0, 6)
        )
        ttk.Button(toolbar, text="Open Folder…", command=self.open_folder).grid(
            row=0, column=1, padx=(0, 12)
        )
        ttk.Label(toolbar, text="Search:").grid(row=0, column=2, padx=(0, 4))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._apply_filter())
        search_entry = ttk.Entry(toolbar, textvariable=self.search_var)
        search_entry.grid(row=0, column=3, sticky="ew", padx=(0, 12))

        self.fit_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            toolbar, text="Fit to window", variable=self.fit_var,
            command=self._update_preview
        ).grid(row=0, column=4, padx=(0, 6))
        ttk.Button(toolbar, text="1:1", command=self._show_actual_size).grid(
            row=0, column=5, padx=(0, 4)
        )
        ttk.Button(toolbar, text="Zoom +", command=lambda: self._zoom(1.25)).grid(
            row=0, column=6, padx=(0, 4)
        )
        ttk.Button(toolbar, text="Zoom -", command=lambda: self._zoom(0.8)).grid(
            row=0, column=7, padx=(0, 12)
        )
        ttk.Button(toolbar, text="Import DDS…", command=self.import_image).grid(
            row=0, column=8, padx=(0, 6)
        )
        ttk.Button(toolbar, text="Save AIF…", command=self.save_aif).grid(
            row=0, column=9, padx=(0, 6)
        )
        ttk.Button(toolbar, text="Export…", command=self.export_image).grid(
            row=0, column=10
        )

        main = ttk.PanedWindow(self, orient="horizontal")
        main.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 6))

        left = ttk.Frame(main, padding=(0, 0, 8, 0))
        main.add(left, weight=1)
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)

        self.file_tree = ttk.Treeview(
            left,
            selectmode="extended",
            show="tree",
            columns=("path",),
        )
        self.file_tree.column("#0", width=360, minwidth=240, stretch=True)
        self.file_tree.column("path", width=0, stretch=False)
        self.file_tree.grid(row=0, column=0, sticky="nsew")
        self.file_tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.file_tree.bind("<Double-1>", lambda _: self._load_selected())
        self.file_tree.bind("<Return>", lambda _: self._load_selected())

        list_scroll = ttk.Scrollbar(left, orient="vertical", command=self.file_tree.yview)
        list_scroll.grid(row=0, column=1, sticky="ns")
        self.file_tree.configure(yscrollcommand=list_scroll.set)

        right = ttk.Frame(main)
        main.add(right, weight=4)
        right.rowconfigure(0, weight=1)
        right.columnconfigure(0, weight=1)

        self.canvas = tk.Canvas(right, background="#202020", highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        x_scroll = ttk.Scrollbar(right, orient="horizontal", command=self.canvas.xview)
        x_scroll.grid(row=1, column=0, sticky="ew")
        y_scroll = ttk.Scrollbar(right, orient="vertical", command=self.canvas.yview)
        y_scroll.grid(row=0, column=1, sticky="ns")
        self.canvas.configure(xscrollcommand=x_scroll.set, yscrollcommand=y_scroll.set)

        self.status_var = tk.StringVar(value="Open an .aif file or folder to begin.")
        status = ttk.Label(
            self,
            textvariable=self.status_var,
            padding=(8, 4),
            relief="sunken",
            anchor="w",
        )
        status.grid(row=2, column=0, sticky="ew")

    def open_file(self) -> None:
        paths = filedialog.askopenfilenames(
            parent=self,
            title="Select AIF files",
            filetypes=[("AIF files", "*.aif"), ("All files", "*.*")],
        )
        if not paths:
            return
        self._set_files([Path(path) for path in paths])

    def open_folder(self) -> None:
        path = filedialog.askdirectory(parent=self, title="Select a folder containing AIF files")
        if not path:
            return
        folder = Path(path)
        files = collect_aif_files([folder])
        if not files:
            messagebox.showinfo("No AIF files", "No .aif files were found in that folder.")
            return
        self._set_files(files, root_dir=folder)

    def _setup_drag_and_drop(self) -> None:
        if DND_FILES is None:
            self.status_var.set("Drag-and-drop unavailable: install tkinterdnd2 for drag-and-drop.")
            return
        self.drop_target_register(DND_FILES)
        self.dnd_bind("<<Drop>>", self._on_drop)

    def _on_drop(self, event: tk.Event) -> None:
        try:
            raw_items = self.tk.splitlist(event.data)
        except Exception:
            raw_items = (event.data,)

        paths = [Path(item) for item in raw_items if item]
        files = collect_aif_files(paths)
        if not files:
            messagebox.showinfo(
                "No AIF files",
                "Drag in one or more .aif files, or folders containing .aif files.",
                parent=self,
            )
            return

        folders = [path for path in paths if path.is_dir()]
        root_dir = folders[0] if len(folders) == 1 else None
        self._set_files(files, root_dir=root_dir)
        return "copy"

    def _set_files(
        self,
        files: list[Path],
        *,
        root_dir: Path | None = None,
    ) -> None:
        self.files = files
        self.root_dir = root_dir or self._common_root(files)
        self.filtered_files = files.copy()
        self._populate_tree()
        if files:
            first_item = next(
                (iid for iid, path in self.tree_items.items() if path in files),
                None,
            )
            if first_item:
                self.file_tree.selection_set(first_item)
                self.file_tree.focus(first_item)
                self.file_tree.see(first_item)
            self._load_selected()

    @staticmethod
    def _common_root(files: list[Path]) -> Path | None:
        if not files:
            return None
        try:
            common = files[0].parent
            for path in files[1:]:
                while not path.is_relative_to(common):
                    common = common.parent
                    if common == common.parent:
                        return None
            return common
        except (ValueError, OSError):
            return None

    def _populate_tree(self) -> None:
        self.file_tree.delete(*self.file_tree.get_children())
        self.tree_items.clear()
        if not self.filtered_files:
            return

        base = self.root_dir or self._common_root(self.filtered_files)
        if base is None:
            for path in self.filtered_files:
                iid = self.file_tree.insert("", "end", text=path.name, values=(str(path),))
                self.tree_items[iid] = path
            return

        parents = {path.parent for path in self.filtered_files}
        if len(parents) == 1 and next(iter(parents)) == base:
            for path in self.filtered_files:
                iid = self.file_tree.insert("", "end", text=path.name, values=(str(path),))
                self.tree_items[iid] = path
            return

        root_iid = self.file_tree.insert("", "end", text=base.name, open=True)
        directory_items: dict[Path, str] = {base: root_iid}
        for path in self.filtered_files:
            try:
                relative = path.relative_to(base)
            except ValueError:
                iid = self.file_tree.insert("", "end", text=path.name, values=(str(path),))
                self.tree_items[iid] = path
                continue

            parent_iid = root_iid
            parts = list(relative.parts)
            for index, part in enumerate(parts[:-1]):
                directory = base.joinpath(*parts[: index + 1])
                if directory not in directory_items:
                    parent_path = directory.parent
                    parent_iid = directory_items.get(parent_path, root_iid)
                    directory_items[directory] = self.file_tree.insert(
                        parent_iid, "end", text=part, open=True
                    )
                parent_iid = directory_items[directory]

            iid = self.file_tree.insert(
                parent_iid, "end", text=relative.name, values=(str(path),)
            )
            self.tree_items[iid] = path

    def _apply_filter(self) -> None:
        query = self.search_var.get().strip().lower()
        if query:
            self.filtered_files = [
                path for path in self.files if query in str(path).lower()
            ]
        else:
            self.filtered_files = self.files.copy()
        self._populate_tree()

    def _on_tree_select(self, _event: tk.Event) -> None:
        selection = self.file_tree.selection()
        if selection:
            for iid in reversed(selection):
                path = self.tree_items.get(iid)
                if path is not None and path in self.filtered_files:
                    self._load_path(path)
                    break

    def _load_selected(self) -> None:
        selection = self.file_tree.selection()
        for iid in reversed(selection):
            path = self.tree_items.get(iid)
            if path is not None and path in self.filtered_files:
                self._load_path(path)
                return

    def _selected_aif_paths(self) -> list[Path]:
        paths: list[Path] = []
        for iid in self.file_tree.selection():
            path = self.tree_items.get(iid)
            if path is not None and path in self.filtered_files and path not in paths:
                paths.append(path)
        return paths

    def _load_path(self, path: Path) -> None:
        try:
            image, info, payload, pixel_data = load_aif_bundle(path)
        except Exception as exc:
            self.full_image = None
            self.current_info = None
            self.current_path = None
            self.current_payload = None
            self.current_pixel_data = None
            self._photo = None
            self.canvas.delete("all")
            self.status_var.set(f"Error: {path.name}: {exc}")
            messagebox.showerror("Cannot open AIF", str(exc), parent=self)
            return

        self.full_image = image
        self.current_info = info
        self.current_path = path
        self.current_payload = payload
        self.current_pixel_data = pixel_data
        self.scale = 1.0
        self._update_preview()

    def _show_actual_size(self) -> None:
        if self.full_image is None:
            return
        self.fit_var.set(False)
        self.scale = 1.0
        self._update_preview()

    def _zoom(self, factor: float) -> None:
        if self.full_image is None:
            return
        self.fit_var.set(False)
        self.scale = min(16.0, max(0.05, self.scale * factor))
        self._update_preview()

    def _on_window_configure(self, event: tk.Event) -> None:
        if event.widget is self and self.fit_var.get() and self.full_image is not None:
            self._update_preview()

    def _on_canvas_configure(self, _event: tk.Event) -> None:
        if self.fit_var.get() and self.full_image is not None:
            self._update_preview()

    def _update_preview(self) -> None:
        if self.full_image is None or self.current_info is None:
            return

        canvas_width = max(1, self.canvas.winfo_width())
        canvas_height = max(1, self.canvas.winfo_height())
        if self.fit_var.get():
            self.scale = min(
                canvas_width / self.full_image.width,
                canvas_height / self.full_image.height,
            )

        target_width = max(1, int(self.full_image.width * self.scale))
        target_height = max(1, int(self.full_image.height * self.scale))
        resampling = Image.Resampling.NEAREST if self.scale >= 1 else Image.Resampling.LANCZOS
        preview = self.full_image.resize((target_width, target_height), resampling)
        self._photo = ImageTk.PhotoImage(preview)

        self.canvas.delete("all")
        logical_width = max(target_width, canvas_width)
        logical_height = max(target_height, canvas_height)
        self.canvas.create_image(
            logical_width // 2,
            logical_height // 2,
            anchor="center",
            image=self._photo,
        )
        self.canvas.configure(scrollregion=(0, 0, logical_width, logical_height))
        self.canvas.xview_moveto(0.5 if target_width > canvas_width else 0)
        self.canvas.yview_moveto(0.5 if target_height > canvas_height else 0)

        info = self.current_info
        fit_text = "fit" if self.fit_var.get() else f"{self.scale:.2f}x"
        self.status_var.set(
            f"{info.source.name}  |  {info.width}x{info.height}  |  {info.fourcc} "
            f"(code {info.format_code})  |  {info.bits_per_pixel} bpp  |  "
            f"{info.pixel_bytes:,} px bytes  |  {info.container}  |  {fit_text}"
        )

    def _read_dds_for_aif(self, dds_path: Path, info: AifInfo) -> bytes:
        data = dds_path.read_bytes()
        if len(data) < 128 or data[:4] != b"DDS ":
            raise ValueError(f"{dds_path.name} is not a DDS file")

        image = Image.open(io.BytesIO(data))
        image.load()
        if image.size != (info.width, info.height):
            raise ValueError(
                f"{dds_path.name} is {image.width}x{image.height}, "
                f"but {info.source.name} is {info.width}x{info.height}"
            )

        blocks = read_matching_dds_blocks(dds_path, info.fourcc, info.pixel_bytes)
        if blocks is None:
            raise ValueError(
                f"{dds_path.name} must use the same format as the AIF ({info.fourcc})"
            )
        return blocks

    def _apply_dds_to_current(self, dds_path: Path) -> None:
        if (
            self.full_image is None
            or self.current_info is None
            or self.current_payload is None
        ):
            raise ValueError("open an AIF file before importing a DDS")

        info = self.current_info
        pixel_data = self._read_dds_for_aif(dds_path, info)
        modified_payload = bytearray(self.current_payload)
        modified_payload[info.data_offset : info.data_offset + info.pixel_bytes] = pixel_data
        modified_dds = _make_dds(info, pixel_data)
        modified_image = Image.open(io.BytesIO(modified_dds))
        modified_image.load()

        self.full_image = modified_image
        self.current_payload = bytes(modified_payload)
        self.current_pixel_data = pixel_data
        self.scale = 1.0
        self._update_preview()
        self.status_var.set(
            f"Imported {dds_path.name} into {info.source.name}: "
            f"{info.width}x{info.height} {info.fourcc}"
        )

    def _batch_import(self, aif_paths: list[Path]) -> None:
        sources = filedialog.askopenfilenames(
            parent=self,
            title="Select DDS files matching the selected AIF files",
            filetypes=[("DDS image", "*.dds"), ("All files", "*.*")],
        )
        if not sources:
            return

        dds_by_stem: dict[str, Path] = {}
        for source in sources:
            path = Path(source)
            if path.suffix.lower() != ".dds":
                continue
            if path.stem in dds_by_stem:
                raise ValueError(f"duplicate DDS filename: {path.stem}")
            dds_by_stem[path.stem] = path

        missing = [path.stem for path in aif_paths if path.stem not in dds_by_stem]
        extra = [stem for stem in dds_by_stem if stem not in {path.stem for path in aif_paths}]
        if missing:
            raise ValueError(
                "No matching DDS for: " + ", ".join(missing[:10]) +
                ("" if len(missing) <= 10 else " …")
            )
        if extra:
            raise ValueError(
                "DDS files without matching AIF: " + ", ".join(extra[:10]) +
                ("" if len(extra) <= 10 else " …")
            )

        output_dir = filedialog.askdirectory(
            parent=self, title="Select the output folder for patched AIF files"
        )
        if not output_dir:
            return
        output = Path(output_dir)

        targets = [output / f"{path.stem}.patched.aif" for path in aif_paths]
        if any(target.exists() for target in targets):
            overwrite = messagebox.askyesno(
                "Overwrite files?",
                "One or more patched AIF files already exist.\n\nOverwrite them?",
                parent=self,
            )
            if not overwrite:
                return

        completed = 0
        errors: list[str] = []
        for aif_path, target in zip(aif_paths, targets):
            try:
                _, info, payload, _ = load_aif_bundle(aif_path)
                dds_path = dds_by_stem[aif_path.stem]
                blocks = self._read_dds_for_aif(dds_path, info)
                modified = bytearray(payload)
                modified[info.data_offset : info.data_offset + info.pixel_bytes] = blocks
                key = bytes.fromhex(info.slz_key or "00000000")
                target.write_bytes(slz_pack(bytes(modified), key))
                completed += 1
            except Exception as exc:
                errors.append(f"{aif_path.name}: {exc}")

        self.status_var.set(f"Batch import: {completed}/{len(aif_paths)} AIF files saved")
        if errors:
            messagebox.showerror(
                "Batch import finished with errors", "\n".join(errors), parent=self
            )

    def import_image(self) -> None:
        selected = self._selected_aif_paths()
        if not selected and self.current_path is not None:
            selected = [self.current_path]
        if not selected:
            messagebox.showinfo("No AIF", "Select one or more AIF files first.")
            return

        try:
            if len(selected) == 1:
                if self.current_path != selected[0]:
                    self._load_path(selected[0])
                source = filedialog.askopenfilename(
                    parent=self,
                    title="Select a DDS file",
                    filetypes=[("DDS image", "*.dds"), ("All files", "*.*")],
                )
                if not source:
                    return
                source_path = Path(source)
                if source_path.stem != self.current_path.stem:
                    raise ValueError(
                        f"DDS filename must match the AIF filename: "
                        f"{self.current_path.stem}.dds"
                    )
                self._apply_dds_to_current(source_path)
            else:
                self._batch_import(selected)
        except Exception as exc:
            messagebox.showerror("Import failed", str(exc), parent=self)

    def save_aif(self) -> None:
        if (
            self.full_image is None
            or self.current_info is None
            or self.current_payload is None
            or self.current_path is None
        ):
            messagebox.showinfo("No AIF", "Open and optionally import an image first.")
            return

        default_name = self.current_path.stem + ".patched.aif"
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Save modified AIF",
            defaultextension=".aif",
            initialfile=default_name,
            filetypes=[("AIF file", "*.aif")],
        )
        if not path:
            return

        target = Path(path)
        if target.exists():
            overwrite = messagebox.askyesno(
                "Overwrite file?",
                f"{target} already exists.\n\nOverwrite it?",
                parent=self,
            )
            if not overwrite:
                return

        try:
            info = self.current_info
            key = bytes.fromhex(info.slz_key or "00000000")
            data = slz_pack(self.current_payload, key)
            target.write_bytes(data)
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc), parent=self)
            return

        self.status_var.set(f"Saved AIF: {target}")

    def export_image(self) -> None:
        selected = self._selected_aif_paths()
        if not selected and self.current_path is not None:
            selected = [self.current_path]
        if not selected:
            messagebox.showinfo("No image", "Select one or more AIF files first.")
            return

        try:
            if len(selected) == 1:
                path = selected[0]
                if self.current_path != path:
                    self._load_path(path)
                if (
                    self.full_image is None
                    or self.current_info is None
                    or self.current_pixel_data is None
                ):
                    raise ValueError("could not load the selected AIF")

                default_name = self.current_path.stem + ".dds"
                target_name = filedialog.asksaveasfilename(
                    parent=self,
                    title="Export current AIF",
                    defaultextension=".dds",
                    initialfile=default_name,
                    filetypes=[
                        ("DDS image", "*.dds"),
                        ("PNG image", "*.png"),
                    ],
                )
                if not target_name:
                    return

                target = Path(target_name)
                if target.suffix.lower() == ".png":
                    self.full_image.save(target, format="PNG")
                else:
                    dds_data = _make_dds(self.current_info, self.current_pixel_data)
                    target.write_bytes(dds_data)
                self.status_var.set(f"Exported: {target}")
                return

            output_dir = filedialog.askdirectory(
                parent=self, title="Select the output folder for DDS files"
            )
            if not output_dir:
                return
            output = Path(output_dir)

            targets = [output / f"{path.stem}.dds" for path in selected]
            if any(target.exists() for target in targets):
                overwrite = messagebox.askyesno(
                    "Overwrite files?",
                    "One or more DDS files already exist.\n\nOverwrite them?",
                    parent=self,
                )
                if not overwrite:
                    return

            completed = 0
            errors: list[str] = []
            for path in selected:
                try:
                    _, info, _, pixel_data = load_aif_bundle(path)
                    target = output / f"{path.stem}.dds"
                    target.write_bytes(_make_dds(info, pixel_data))
                    completed += 1
                except Exception as exc:
                    errors.append(f"{path.name}: {exc}")

            self.status_var.set(f"Batch export: {completed}/{len(selected)} DDS files")
            if errors:
                messagebox.showerror(
                    "Batch export finished with errors", "\n".join(errors), parent=self
                )
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc), parent=self)


def run_self_test(paths: list[Path]) -> int:
    files = collect_aif_files(paths)
    if not files:
        print("No .aif files found.")
        return 1

    failures = 0
    for path in files:
        try:
            image, info = decode_aif(path)
            print(
                f"OK {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}: "
                f"{info.width}x{info.height} {info.fourcc} "
                f"payload={info.payload_size} pixels={info.pixel_bytes}"
            )
        except Exception as exc:
            failures += 1
            print(f"FAIL {path}: {exc}")

    print(f"{len(files) - failures}/{len(files)} files decoded successfully.")
    return 0 if failures == 0 else 1


def main() -> int:
    if "--self-test" in sys.argv:
        paths = [Path(item) for item in sys.argv[2:] if item != "--self-test"]
        if not paths:
            paths = [ROOT / "sprite_ja-jp" / "asset" / "sprite"]
        return run_self_test(paths)

    app = AifViewer()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
