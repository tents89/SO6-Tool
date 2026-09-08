# STAR OCEAN: THE DIVINE FORCE Localization Tools

This folder contains four standalone tools for working with game text, CPK archives, fonts, and AIF textures.

## Table of Contents

* [Requirements](#requirements)
* [Quick Start](#quick-start)
* [Text Tool](#text-tool)
* [CPK Tool](#cpk-tool)
* [Font Tool](#font-tool)
* [AIF Viewer and Editor](#aif-viewer-and-editor)
* [Recommended Workflow](#recommended-workflow)

## Requirements

* Python 3.10 or newer
* `zstandard`
* `Pillow`
* `tkinterdnd2` — optional, used for drag-and-drop support in the AIF viewer

Install the required packages:

```powershell
python -m pip install zstandard Pillow
```

To enable drag-and-drop support:

```powershell
python -m pip install tkinterdnd2
```

## Quick Start

Game assets are packaged inside CPK archives. To extract them, search GitHub for `esperknight/CriPakTools` or `Youjose/CriCodecs`.

|Tool|File|Purpose|
|-|-|-|
|Text tool|`text/slz\\\_msgp.py`|Extract, edit, and rebuild message `.bin` files|
|CPK tool|`cpkpatch/cpkpatch.py`|Inspect and replace files inside CPK archives|
|Font tool|`font/font\\\_xor.py`|Decrypt and encrypt fonts|
|AIF tool|`aif\\\_viewer.py`|Browse, import, export, and repack AIF textures|

## Text Tool

The text tool processes game message `.bin` files. It unwraps the SLZ container and then parses the internal MSGP FlatBuffers data.

### Extract Messages

```powershell
python tools/text/slz\\\_msgp.py extract Your\\\_Message\\\_Files -o Your\\\_Json\\\_Files -t Your\\\_Translation.tsv
```

This creates:

* One JSON file for each message file
* One TSV translation worklist

The TSV columns are:

```text
file    key    name\\\_key    text
```

`name\\\_key` is optional. Leave it empty if the original message does not have one.

### Rebuild Messages

After editing the TSV, run:

```powershell
python tools/text/slz\\\_msgp.py build Your\\\_Translation.tsv -j Your\\\_Json\\\_Files -o Your\\\_Built\\\_Files
```

This applies the TSV edits to the JSON files and writes rebuilt `.bin` files to `Your\\\_Built\\\_Files`.

### Export Raw MSGP

If you only need the raw FlatBuffers payload, without JSON conversion:

```powershell
python tools/text/slz\\\_msgp.py msgp Your\\\_Message\\\_Files -o Your\\\_Msgp\\\_Files
```

### Validation and Self-Test

```powershell
python tools/text/slz\\\_msgp.py verify Your\\\_Built\\\_Files
python tools/text/slz\\\_msgp.py roundtrip Your\\\_Message\\\_Files/Your\\\_Sample.bin
```

## CPK Tool

The CPK tool inspects CRI CPK archives and replaces files without rebuilding the entire archive.

### Inspect a CPK

```powershell
python tools/cpkpatch/cpkpatch.py info -p Your\\\_CPK.cpk
```

### List Files in a CPK

```powershell
python tools/cpkpatch/cpkpatch.py list -p Your\\\_CPK.cpk -f Your\\\_Filter
```

### Patch a CPK

```powershell
python tools/cpkpatch/cpkpatch.py patch -p Your\\\_CPK.cpk -i Your\\\_Built\\\_Files
```

Useful options:

* `--backup` — create a `.bak` backup before patching
* `--dry-run` — show what would change without writing
* `--strict` — stop if an input file cannot be matched
* `--no-verify` — skip post-patch verification

## Font Tool

The font tool handles the game's XOR-encrypted font files.

### Decrypt a Font

```powershell
python tools/font/font\\\_xor.py decrypt Your\\\_Font.ttf
```

Outputs are written next to the script:

```text
decrypt/Your\\\_Font.ttf
decrypt/Your\\\_Font.xor
```

The `.xor` file contains the original 4-byte XOR key.

### Encrypt a Font

```powershell
python tools/font/font\\\_xor.py encrypt decrypt/Your\\\_Font.ttf
```

The encrypted font is written to:

```text
encrypt/Your\\\_Font.ttf
```

## AIF Viewer and Editor

The AIF tool browses, previews, imports, exports, and repacks SLZ-wrapped AIF textures.

### Start the GUI

```powershell
python tools/aif\\\_viewer.py
```

Features include:

* Open one or more `.aif` files
* Open an entire folder
* Drag and drop `.aif` files or folders (`tkinterdnd2` required)
* Tree-style file list
* Shift / Ctrl multi-selection
* DXT1 / DXT3 / DXT5 preview
* Export to DDS or PNG
* Import DDS files and repack them as SLZ-wrapped AIF files

### Modify an AIF

1. Open one or more `.aif` files.
2. Choose **Import DDS…**.
3. Select a DDS file with the same base filename as the AIF.
4. Make sure the DDS dimensions and DXT format match the AIF.
5. Choose **Save AIF…**. The result is always repacked as SLZ.

For single-file import, the DDS base filename must match the AIF base filename.

### Batch Operations

Use Shift or Ctrl in the left file tree to select multiple AIF files:

* **Export…** — batch-export the selected files as DDS files into one folder
* **Import DDS…** — select multiple DDS files whose filenames match the selected AIF files; output is written as `original\\\_name.patched.aif`

Batch import automatically:

* Checks DDS and AIF dimensions
* Checks the DXT format
* Checks the pixel data size
* Repacks using the original SLZ key

### Non-GUI Validation

```powershell
python tools/aif\\\_viewer.py --self-test tools/sprite\\\_ja-jp/asset/sprite
```

## Recommended Workflow

1. Use the CPK tool to extract message or asset files.
2. Modify the content with the text tool or AIF tool.
3. Rebuild or export the modified files.
4. Use the CPK tool to write the new files back into the CPK.
5. If necessary, handle font encryption at the same time.

