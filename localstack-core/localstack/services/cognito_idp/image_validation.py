from __future__ import annotations

import math
import struct
from array import array
from dataclasses import dataclass


class ImageValidationError(ValueError):
    pass


@dataclass(frozen=True)
class _Component:
    identifier: int
    horizontal: int
    vertical: int
    quantization: int


@dataclass(frozen=True)
class _HuffmanTable:
    codes: dict[tuple[int, int], int]
    maximum_length: int

    def decode(self, reader: _BitReader) -> int:
        code = 0
        for length in range(1, self.maximum_length + 1):
            code = (code << 1) | reader.read(1)
            symbol = self.codes.get((length, code))
            if symbol is not None:
                return symbol
        raise ImageValidationError("Invalid JPEG Huffman code")


class _BitReader:
    def __init__(self, content: bytes):
        self.content = content
        self.bit_offset = 0

    def read(self, count: int) -> int:
        if count < 0 or self.bit_offset + count > len(self.content) * 8:
            raise ImageValidationError("Truncated JPEG entropy stream")
        value = 0
        for _ in range(count):
            byte = self.content[self.bit_offset >> 3]
            value = (value << 1) | ((byte >> (7 - (self.bit_offset & 7))) & 1)
            self.bit_offset += 1
        return value

    def finish(self) -> None:
        remaining = len(self.content) * 8 - self.bit_offset
        if remaining > 7:
            raise ImageValidationError("Unused JPEG entropy bytes")
        if remaining and self.read(remaining) != (1 << remaining) - 1:
            raise ImageValidationError("Invalid JPEG entropy padding")


@dataclass
class _Frame:
    marker: int
    width: int
    height: int
    components: dict[int, _Component]

    @property
    def progressive(self) -> bool:
        return self.marker == 0xC2

    @property
    def max_horizontal(self) -> int:
        return max(item.horizontal for item in self.components.values())

    @property
    def max_vertical(self) -> int:
        return max(item.vertical for item in self.components.values())


def validate_jpeg(
    content: bytes,
    *,
    max_width: int,
    max_height: int,
    max_pixels: int,
) -> tuple[int, int]:
    """Validate a complete Huffman JPEG stream without allocating a raster image.

    Baseline and progressive 8-bit DCT streams are entropy-decoded coefficient by
    coefficient. This deliberately rejects arithmetic, lossless, hierarchical and
    12-bit JPEG variants instead of accepting an envelope that no supported decoder
    has proved readable.
    """

    if not isinstance(content, bytes) or len(content) < 4 or content[:2] != b"\xff\xd8":
        raise ImageValidationError("Invalid JPEG signature")
    if not all(
        isinstance(limit, int) and limit > 0 for limit in (max_width, max_height, max_pixels)
    ):
        raise ImageValidationError("Invalid JPEG validation budget")

    quantization_tables: set[int] = set()
    huffman_tables: dict[tuple[int, int], _HuffmanTable] = {}
    frame: _Frame | None = None
    restart_interval = 0
    sequential_components: set[int] = set()
    progressive_levels: dict[int, list[int | None]] = {}
    coefficient_masks: dict[int, array] = {}
    scan_count = 0
    offset = 2

    while offset < len(content):
        marker, marker_offset, offset = _read_marker(content, offset)
        if marker == 0xD9:
            if offset != len(content) or frame is None or scan_count == 0:
                raise ImageValidationError("Invalid JPEG end marker")
            if frame.progressive:
                if any(
                    any(level is None for level in levels) for levels in progressive_levels.values()
                ):
                    raise ImageValidationError("Incomplete progressive JPEG scans")
            elif sequential_components != set(frame.components):
                raise ImageValidationError("Incomplete sequential JPEG scans")
            return frame.width, frame.height
        if marker in {0xD8, 0x01, *range(0xD0, 0xD8)}:
            raise ImageValidationError("Unexpected standalone JPEG marker")
        if marker == 0xDA:
            if frame is None:
                raise ImageValidationError("JPEG scan precedes frame")
            segment, offset = _read_segment(content, offset)
            scan_offset = offset
            parts, restart_markers, offset = _entropy_parts(content, scan_offset)
            selected, spectral_start, spectral_end, approximation_high, approximation_low = (
                _parse_scan_header(segment, frame)
            )
            for component, dc_table, ac_table in selected:
                if component.quantization not in quantization_tables:
                    raise ImageValidationError("Missing JPEG quantization table")
                if (
                    spectral_start == 0
                    and approximation_high == 0
                    and (0, dc_table) not in huffman_tables
                ):
                    raise ImageValidationError("Missing JPEG DC Huffman table")
                if (
                    spectral_end > 0
                    and approximation_high == 0
                    and (1, ac_table) not in huffman_tables
                ):
                    raise ImageValidationError("Missing JPEG AC Huffman table")
            if frame.progressive:
                _validate_progressive_scan(
                    frame,
                    selected,
                    spectral_start,
                    spectral_end,
                    approximation_high,
                    approximation_low,
                    parts,
                    restart_markers,
                    restart_interval,
                    huffman_tables,
                    progressive_levels,
                    coefficient_masks,
                )
            else:
                if (spectral_start, spectral_end, approximation_high, approximation_low) != (
                    0,
                    63,
                    0,
                    0,
                ):
                    raise ImageValidationError("Invalid sequential JPEG scan parameters")
                identifiers = {item[0].identifier for item in selected}
                if sequential_components & identifiers:
                    raise ImageValidationError("Duplicate sequential JPEG component scan")
                _validate_sequential_scan(
                    frame,
                    selected,
                    parts,
                    restart_markers,
                    restart_interval,
                    huffman_tables,
                )
                sequential_components.update(identifiers)
            scan_count += 1
            if scan_count > 256:
                raise ImageValidationError("Too many JPEG scans")
            continue

        segment, offset = _read_segment(content, offset)
        if marker == 0xDB:
            _parse_quantization_tables(segment, quantization_tables)
        elif marker == 0xC4:
            _parse_huffman_tables(segment, huffman_tables)
        elif marker in {0xC0, 0xC1, 0xC2}:
            if frame is not None:
                raise ImageValidationError("Multiple JPEG frames are not supported")
            frame = _parse_frame(
                marker,
                segment,
                max_width=max_width,
                max_height=max_height,
                max_pixels=max_pixels,
            )
            if frame.progressive:
                for identifier, component in frame.components.items():
                    progressive_levels[identifier] = [None] * 64
                    columns, rows = _single_component_grid(frame, component)
                    coefficient_masks[identifier] = array("Q", [0]) * (columns * rows)
        elif marker == 0xDD:
            if len(segment) != 2:
                raise ImageValidationError("Invalid JPEG restart interval")
            restart_interval = struct.unpack(">H", segment)[0]
        elif marker in {
            0xC3,
            0xC5,
            0xC6,
            0xC7,
            0xC9,
            0xCA,
            0xCB,
            0xCD,
            0xCE,
            0xCF,
            0xDC,
            0xDE,
            0xDF,
        }:
            raise ImageValidationError("Unsupported JPEG coding process")
        elif marker_offset == 2 and marker not in {*range(0xE0, 0xF0), 0xFE, 0xDB, 0xC4}:
            raise ImageValidationError("Invalid JPEG marker ordering")

    raise ImageValidationError("Missing JPEG end marker")


def validate_webp(
    content: bytes,
    *,
    max_width: int,
    max_height: int,
    max_pixels: int,
) -> tuple[int, int]:
    del content, max_width, max_height, max_pixels
    raise ImageValidationError(
        "WEBP is not accepted by any current Cognito managed-login asset category"
    )


def _read_marker(content: bytes, offset: int) -> tuple[int, int, int]:
    marker_offset = offset
    if offset >= len(content) or content[offset] != 0xFF:
        raise ImageValidationError("Invalid JPEG marker framing")
    while offset < len(content) and content[offset] == 0xFF:
        offset += 1
    if offset >= len(content) or content[offset] in {0x00, 0xFF}:
        raise ImageValidationError("Invalid JPEG marker")
    return content[offset], marker_offset, offset + 1


def _read_segment(content: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 2 > len(content):
        raise ImageValidationError("Truncated JPEG segment")
    length = struct.unpack(">H", content[offset : offset + 2])[0]
    end = offset + length
    if length < 2 or end > len(content):
        raise ImageValidationError("Invalid JPEG segment length")
    return content[offset + 2 : end], end


def _parse_quantization_tables(segment: bytes, tables: set[int]) -> None:
    offset = 0
    while offset < len(segment):
        definition = segment[offset]
        offset += 1
        precision, identifier = definition >> 4, definition & 0x0F
        size = 64 * (precision + 1)
        if precision not in {0, 1} or identifier > 3 or offset + size > len(segment):
            raise ImageValidationError("Invalid JPEG quantization table")
        values = segment[offset : offset + size]
        if precision == 0:
            valid = all(values)
        else:
            valid = all(values[index : index + 2] != b"\0\0" for index in range(0, size, 2))
        if not valid:
            raise ImageValidationError("Invalid JPEG quantization value")
        tables.add(identifier)
        offset += size
    if not segment:
        raise ImageValidationError("Empty JPEG quantization segment")


def _parse_huffman_tables(segment: bytes, tables: dict[tuple[int, int], _HuffmanTable]) -> None:
    offset = 0
    while offset < len(segment):
        if offset + 17 > len(segment):
            raise ImageValidationError("Truncated JPEG Huffman table")
        definition = segment[offset]
        table_class, identifier = definition >> 4, definition & 0x0F
        counts = segment[offset + 1 : offset + 17]
        symbol_count = sum(counts)
        offset += 17
        if (
            table_class not in {0, 1}
            or identifier > 3
            or symbol_count == 0
            or symbol_count > 256
            or offset + symbol_count > len(segment)
        ):
            raise ImageValidationError("Invalid JPEG Huffman table")
        symbols = segment[offset : offset + symbol_count]
        offset += symbol_count
        code = 0
        codes: dict[tuple[int, int], int] = {}
        symbol_offset = 0
        maximum_length = 0
        for length, count in enumerate(counts, 1):
            if code + count > 1 << length:
                raise ImageValidationError("Oversubscribed JPEG Huffman table")
            for _ in range(count):
                if code == (1 << length) - 1:
                    raise ImageValidationError("JPEG Huffman table uses reserved all-ones code")
                codes[(length, code)] = symbols[symbol_offset]
                symbol_offset += 1
                code += 1
                maximum_length = length
            code <<= 1
        tables[(table_class, identifier)] = _HuffmanTable(codes, maximum_length)
    if not segment:
        raise ImageValidationError("Empty JPEG Huffman segment")


def _parse_frame(
    marker: int,
    segment: bytes,
    *,
    max_width: int,
    max_height: int,
    max_pixels: int,
) -> _Frame:
    if len(segment) < 6:
        raise ImageValidationError("Truncated JPEG frame")
    precision, height, width, count = struct.unpack(">BHHB", segment[:6])
    if precision != 8 or count not in {1, 3, 4} or len(segment) != 6 + 3 * count:
        raise ImageValidationError("Unsupported JPEG frame")
    if not 1 <= width <= max_width or not 1 <= height <= max_height or width * height > max_pixels:
        raise ImageValidationError("JPEG dimensions exceed validation budget")
    components: dict[int, _Component] = {}
    sampling_sum = 0
    for offset in range(6, len(segment), 3):
        identifier, sampling, quantization = segment[offset : offset + 3]
        horizontal, vertical = sampling >> 4, sampling & 0x0F
        if (
            identifier in components
            or not 1 <= horizontal <= 4
            or not 1 <= vertical <= 4
            or quantization > 3
        ):
            raise ImageValidationError("Invalid JPEG frame component")
        sampling_sum += horizontal * vertical
        components[identifier] = _Component(identifier, horizontal, vertical, quantization)
    if sampling_sum > 10:
        raise ImageValidationError("JPEG sampling factors exceed decoder budget")
    return _Frame(marker, width, height, components)


def _parse_scan_header(
    segment: bytes, frame: _Frame
) -> tuple[list[tuple[_Component, int, int]], int, int, int, int]:
    if not segment:
        raise ImageValidationError("Empty JPEG scan header")
    count = segment[0]
    if count == 0 or count > 4 or len(segment) != 1 + 2 * count + 3:
        raise ImageValidationError("Invalid JPEG scan header")
    selected: list[tuple[_Component, int, int]] = []
    seen = set()
    for offset in range(1, 1 + 2 * count, 2):
        identifier, tables = segment[offset : offset + 2]
        if identifier in seen or identifier not in frame.components:
            raise ImageValidationError("Invalid JPEG scan component")
        seen.add(identifier)
        dc_table, ac_table = tables >> 4, tables & 0x0F
        if dc_table > 3 or ac_table > 3:
            raise ImageValidationError("Invalid JPEG scan table selector")
        selected.append((frame.components[identifier], dc_table, ac_table))
    spectral_start, spectral_end, approximation = segment[-3:]
    approximation_high, approximation_low = approximation >> 4, approximation & 0x0F
    if not 0 <= spectral_start <= spectral_end <= 63:
        raise ImageValidationError("Invalid JPEG spectral selection")
    return selected, spectral_start, spectral_end, approximation_high, approximation_low


def _entropy_parts(content: bytes, offset: int) -> tuple[list[bytes], list[int], int]:
    parts: list[bytes] = []
    restart_markers: list[int] = []
    current = bytearray()
    while offset < len(content):
        value = content[offset]
        if value != 0xFF:
            current.append(value)
            offset += 1
            continue
        marker_offset = offset
        offset += 1
        if offset >= len(content):
            raise ImageValidationError("Truncated JPEG entropy marker")
        marker = content[offset]
        if marker == 0x00:
            current.append(0xFF)
            offset += 1
            continue
        if marker == 0xFF:
            raise ImageValidationError("Ambiguous fill byte in JPEG entropy stream")
        if 0xD0 <= marker <= 0xD7:
            parts.append(bytes(current))
            current.clear()
            restart_markers.append(marker)
            offset += 1
            continue
        parts.append(bytes(current))
        return parts, restart_markers, marker_offset
    raise ImageValidationError("JPEG entropy stream has no following marker")


def _single_component_grid(frame: _Frame, component: _Component) -> tuple[int, int]:
    columns = math.ceil(frame.width * component.horizontal / (8 * frame.max_horizontal))
    rows = math.ceil(frame.height * component.vertical / (8 * frame.max_vertical))
    return columns, rows


def _scan_layout(
    frame: _Frame, selected: list[tuple[_Component, int, int]]
) -> tuple[int, list[tuple[_Component, int, int]]]:
    if len(selected) == 1:
        component = selected[0][0]
        columns, rows = _single_component_grid(frame, component)
        return columns * rows, [(component, 1, 0)]
    columns = math.ceil(frame.width / (8 * frame.max_horizontal))
    rows = math.ceil(frame.height / (8 * frame.max_vertical))
    layout = [(item[0], item[0].horizontal * item[0].vertical, 0) for item in selected]
    return columns * rows, layout


def _read_entropy_mcus(
    *,
    mcu_count: int,
    parts: list[bytes],
    restart_markers: list[int],
    restart_interval: int,
    callback,
) -> None:
    if not parts or len(parts) != len(restart_markers) + 1:
        raise ImageValidationError("Invalid JPEG entropy partition")
    if restart_markers and restart_interval == 0:
        raise ImageValidationError("Unexpected JPEG restart marker")
    part_index = 0
    reader = _BitReader(parts[0])
    expected_restart = 0
    for mcu_index in range(mcu_count):
        if restart_interval and mcu_index and mcu_index % restart_interval == 0:
            reader.finish()
            if (
                part_index >= len(restart_markers)
                or restart_markers[part_index] != 0xD0 + expected_restart
            ):
                raise ImageValidationError("Invalid JPEG restart sequence")
            expected_restart = (expected_restart + 1) & 7
            part_index += 1
            reader = _BitReader(parts[part_index])
        callback(reader, mcu_index, bool(restart_interval and mcu_index % restart_interval == 0))
    reader.finish()
    if part_index != len(parts) - 1:
        raise ImageValidationError("Excess JPEG restart partitions")


def _validate_sequential_scan(
    frame: _Frame,
    selected: list[tuple[_Component, int, int]],
    parts: list[bytes],
    restart_markers: list[int],
    restart_interval: int,
    tables: dict[tuple[int, int], _HuffmanTable],
) -> None:
    mcu_count, layout = _scan_layout(frame, selected)
    selections = {item[0].identifier: item for item in selected}

    def decode_mcu(reader: _BitReader, _index: int, _restart: bool) -> None:
        for component, block_count, _ in layout:
            _, dc_identifier, ac_identifier = selections[component.identifier]
            dc = tables[(0, dc_identifier)]
            ac = tables[(1, ac_identifier)]
            for _ in range(block_count):
                category = dc.decode(reader)
                if category > 11:
                    raise ImageValidationError("Invalid sequential JPEG DC category")
                reader.read(category)
                coefficient = 1
                while coefficient < 64:
                    symbol = ac.decode(reader)
                    run, size = symbol >> 4, symbol & 0x0F
                    if size == 0:
                        if run == 0:
                            break
                        if run != 15:
                            raise ImageValidationError("Invalid sequential JPEG AC symbol")
                        coefficient += 16
                    else:
                        if size > 10:
                            raise ImageValidationError("Invalid sequential JPEG AC category")
                        coefficient += run
                        if coefficient >= 64:
                            raise ImageValidationError("Sequential JPEG AC run exceeds block")
                        reader.read(size)
                        coefficient += 1
                    if coefficient > 64:
                        raise ImageValidationError("Sequential JPEG AC run exceeds block")

    _read_entropy_mcus(
        mcu_count=mcu_count,
        parts=parts,
        restart_markers=restart_markers,
        restart_interval=restart_interval,
        callback=decode_mcu,
    )


def _validate_progressive_scan(
    frame: _Frame,
    selected: list[tuple[_Component, int, int]],
    spectral_start: int,
    spectral_end: int,
    approximation_high: int,
    approximation_low: int,
    parts: list[bytes],
    restart_markers: list[int],
    restart_interval: int,
    tables: dict[tuple[int, int], _HuffmanTable],
    levels: dict[int, list[int | None]],
    masks: dict[int, array],
) -> None:
    if approximation_high > 13 or approximation_low > 13:
        raise ImageValidationError("Invalid progressive JPEG approximation")
    if spectral_start == 0:
        if spectral_end != 0:
            raise ImageValidationError("Progressive JPEG DC scan must select coefficient zero")
    elif len(selected) != 1:
        raise ImageValidationError("Progressive JPEG AC scans must be non-interleaved")
    if approximation_high and approximation_low != approximation_high - 1:
        raise ImageValidationError("Invalid progressive JPEG refinement")
    for component, _, _ in selected:
        band = levels[component.identifier][spectral_start : spectral_end + 1]
        if approximation_high == 0:
            if any(level is not None for level in band):
                raise ImageValidationError("Duplicate progressive JPEG first scan")
        elif any(level != approximation_high for level in band):
            raise ImageValidationError("Progressive JPEG refinement precedes first scan")

    mcu_count, layout = _scan_layout(frame, selected)
    selections = {item[0].identifier: item for item in selected}
    eob_run = 0

    def decode_mcu(reader: _BitReader, mcu_index: int, restart: bool) -> None:
        nonlocal eob_run
        if restart:
            eob_run = 0
        for component, block_count, _ in layout:
            _, dc_identifier, ac_identifier = selections[component.identifier]
            for block_offset in range(block_count):
                if spectral_start == 0:
                    if approximation_high == 0:
                        category = tables[(0, dc_identifier)].decode(reader)
                        if category > 11:
                            raise ImageValidationError("Invalid progressive JPEG DC category")
                        reader.read(category)
                    else:
                        reader.read(1)
                    continue
                block_index = mcu_index + block_offset
                mask = masks[component.identifier][block_index]
                if approximation_high == 0:
                    mask, eob_run = _decode_progressive_ac_first(
                        reader,
                        tables[(1, ac_identifier)],
                        mask,
                        spectral_start,
                        spectral_end,
                        eob_run,
                    )
                else:
                    mask, eob_run = _decode_progressive_ac_refine(
                        reader,
                        tables[(1, ac_identifier)],
                        mask,
                        spectral_start,
                        spectral_end,
                        eob_run,
                    )
                masks[component.identifier][block_index] = mask

    _read_entropy_mcus(
        mcu_count=mcu_count,
        parts=parts,
        restart_markers=restart_markers,
        restart_interval=restart_interval,
        callback=decode_mcu,
    )
    if eob_run:
        raise ImageValidationError("Progressive JPEG EOB run exceeds scan")
    for component, _, _ in selected:
        levels[component.identifier][spectral_start : spectral_end + 1] = [approximation_low] * (
            spectral_end - spectral_start + 1
        )


def _decode_progressive_ac_first(
    reader: _BitReader,
    table: _HuffmanTable,
    mask: int,
    start: int,
    end: int,
    eob_run: int,
) -> tuple[int, int]:
    if eob_run:
        return mask, eob_run - 1
    coefficient = start
    while coefficient <= end:
        symbol = table.decode(reader)
        run, size = symbol >> 4, symbol & 0x0F
        if size == 0:
            if run == 15:
                coefficient += 16
                if coefficient > end + 1:
                    raise ImageValidationError("Progressive JPEG zero run exceeds band")
                continue
            return mask, ((1 << run) + reader.read(run)) - 1
        if size > 10:
            raise ImageValidationError("Invalid progressive JPEG AC category")
        coefficient += run
        if coefficient > end:
            raise ImageValidationError("Progressive JPEG AC run exceeds band")
        reader.read(size)
        mask |= 1 << coefficient
        coefficient += 1
    return mask, 0


def _decode_progressive_ac_refine(
    reader: _BitReader,
    table: _HuffmanTable,
    mask: int,
    start: int,
    end: int,
    eob_run: int,
) -> tuple[int, int]:
    coefficient = start
    if not eob_run:
        while coefficient <= end:
            symbol = table.decode(reader)
            run, size = symbol >> 4, symbol & 0x0F
            if size not in {0, 1}:
                raise ImageValidationError("Invalid progressive JPEG refinement symbol")
            if size == 0 and run < 15:
                eob_run = (1 << run) + reader.read(run)
                break
            zeros = 16 if size == 0 else run
            if size == 1:
                reader.read(1)
            while coefficient <= end:
                if mask & (1 << coefficient):
                    reader.read(1)
                else:
                    if zeros == 0:
                        break
                    zeros -= 1
                coefficient += 1
            if zeros or (size == 1 and coefficient > end):
                raise ImageValidationError("Progressive JPEG refinement run exceeds band")
            if size == 1:
                mask |= 1 << coefficient
                coefficient += 1
    if eob_run:
        while coefficient <= end:
            if mask & (1 << coefficient):
                reader.read(1)
            coefficient += 1
        eob_run -= 1
    return mask, eob_run
