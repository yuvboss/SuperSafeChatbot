import io
import zipfile

SCANNABLE_EXTENSIONS = {".py", ".js", ".ts", ".env", ".txt", ".yaml", ".yml", ".json"}
MAX_FILES = 100
MAX_FILE_BYTES = 300_000
MAX_TOTAL_UNCOMPRESSED_BYTES = 25_000_000


def extract_zip(uploaded_file) -> list:
    """Read an uploaded .zip into memory. Returns a list of entry dicts:
    {relpath, raw_bytes, text, scannable}. Raises ValueError if the archive
    trips a size/count guardrail, or isn't a valid zip."""
    data = uploaded_file.read()
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ValueError("That file isn't a valid .zip archive.")

    infos = [i for i in zf.infolist() if not i.is_dir()]
    if len(infos) > MAX_FILES:
        raise ValueError(
            f"That archive has {len(infos)} files, which is over the {MAX_FILES}-file limit. "
            "Please upload a smaller directory."
        )

    total_size = sum(i.file_size for i in infos)
    if total_size > MAX_TOTAL_UNCOMPRESSED_BYTES:
        raise ValueError(
            f"That archive is {total_size / 1e6:.1f} MB uncompressed, which is over the "
            f"{MAX_TOTAL_UNCOMPRESSED_BYTES / 1e6:.0f} MB limit. Please upload a smaller directory."
        )

    entries = []
    for info in infos:
        raw = zf.read(info)
        ext = "." + info.filename.rsplit(".", 1)[-1].lower() if "." in info.filename else ""
        scannable = ext in SCANNABLE_EXTENSIONS and len(raw) <= MAX_FILE_BYTES
        text = None
        if scannable:
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                scannable = False
        entries.append({
            "relpath": info.filename,
            "raw_bytes": raw,
            "text": text,
            "scannable": scannable,
        })
    return entries


def build_zip(entries: list, overrides: dict) -> bytes:
    """Rebuild a zip from entries, substituting overrides[relpath] (fixed text)
    for any accepted files, and the original raw_bytes for everything else."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry in entries:
            fixed_text = overrides.get(entry["relpath"])
            if fixed_text is not None:
                zf.writestr(entry["relpath"], fixed_text)
            else:
                zf.writestr(entry["relpath"], entry["raw_bytes"])
    return buf.getvalue()
