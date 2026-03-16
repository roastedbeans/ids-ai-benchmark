#!/usr/bin/env python3
# coding: utf8

import xml.etree.ElementTree as ET
import csv
import re
import logging
import math
from pathlib import Path
from nas_rrc_headers_ai import nas_rrc_headers_ai


class NASRRCPreprocessor:
    """
    PDML to CSV preprocessor for AI model training (Android variant aligned to modi-parser).
    Extracts metadata + essential fields, normalizes values, and keeps all packets.
    """

    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.packets = []
        # Convert header list to set for faster lookup
        self.essential_fields = set(nas_rrc_headers_ai)

        # Pre-compute sorted fields to avoid repeated sorting (performance optimization)
        self._sorted_fields = sorted(self.essential_fields)

        # Structured storage: keep csv/xml/json/qmdl in consistent containers
        self.base_dir = Path("/sdcard/Documents/MODI/ai")
        self.output_root = self.base_dir / "output"
        self.output_dir = self.output_root / "csv"
        self.xml_dir = self.output_root / "xml"
        self.json_dir = self.output_root / "json"
        self.analyzed_qmdl_dir = self.base_dir / "analyzed_qmdl"
        self.failed_dir = self.base_dir / "failed"
        for d in (
            self.output_root,
            self.output_dir,
            self.xml_dir,
            self.json_dir,
            self.analyzed_qmdl_dir,
            self.failed_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)

    def _convert_hex_hybrid(self, x):
        """
        Convert short hex to int; long hex to entropy. Non-hex -> -1.
        Follows parser logic exactly.
        """
        # Keep -1 exactly as is
        if x == -1 or x == "-1":
            return -1

        # Convert to string
        s = str(x).strip()

        # Empty or NaN
        if s == "" or s.lower() == "nan":
            return -1

        # Remove 0x prefix
        if s.startswith("0x") or s.startswith("0X"):
            s = s[2:]

        # Check if value is hex
        if not all(c in "0123456789abcdefABCDEF" for c in s):
            return -1

        # If hex string is short, safe to convert to int
        if len(s) < 10:
            try:
                return int(s, 16)  # convert safely
            except:
                return -1

        # If hex string is long, compute entropy instead
        freq = {c: s.count(c) for c in set(s)}
        total = len(s)
        # Guard against total == 0 here to prevent ZeroDivisionError
        if total == 0:
            return -1
        entropy = -sum((v / total) * math.log2(v / total) for v in freq.values())
        return entropy

    def _slugify(self, text):
        if not text:
            return ""
        return text.replace('.', '_').lower()

    def _normalize_filename(self, filename):
        if not filename:
            return ""
        if filename.endswith('_output'):
            filename = filename[:-7]
        normalized = filename.replace('-', '_').replace(' ', '_')
        normalized = re.sub(r'[^\w_]', '_', normalized)
        normalized = re.sub(r'_+', '_', normalized)
        normalized = normalized.strip('_')
        return normalized.lower()

    def _classify_packet_type(self, packet):
        protos = packet.findall('.//proto')
        proto_names = [proto.get('name', '').lower() for proto in protos]
        has_nas = 'nas-eps' in proto_names or 'nas-5gs' in proto_names
        has_rrc = any('rrc' in name for name in proto_names)
        has_gsm = 'gsm_a.dtap' in proto_names
        if has_nas and has_rrc:
            return 'nas+rrc'
        elif has_nas:
            return 'nas'
        elif has_rrc:
            return 'rrc'
        elif has_gsm:
            return 'gsm'
        return 'other'

    def _get_packet_direction(self, packet):
        dl_fields = [
            'lte-rrc.DL_DCCH_Message_element', 'lte-rrc.DL_CCCH_Message_element',
            'lte-rrc.BCCH_DL_SCH_Message_element', 'lte-rrc.BCCH_BCH_Message_element',
            'nr-rrc.dl_dcch_message_message', 'nr-rrc.dl_ccch_message_message',
        ]
        ul_fields = [
            'lte-rrc.UL_DCCH_Message_element', 'lte-rrc.UL_CCCH_Message_element',
            'nr-rrc.ul_dcch_message_message', 'nr-rrc.ul_ccch_message_message',
        ]
        for field_name in dl_fields:
            if packet.find(f'.//field[@name="{field_name}"]') is not None:
                return '0'
        for field_name in ul_fields:
            if packet.find(f'.//field[@name="{field_name}"]') is not None:
                return '1'
        gsmtap_uplink = packet.find('.//field[@name="gsmtap.uplink"]')
        if gsmtap_uplink is not None:
            uplink_value = gsmtap_uplink.get('show', '')
            if uplink_value == '0':
                return '0'
            elif uplink_value == '1':
                return '1'
        return None

    def _extract_packet_info(self, packet):
        skip_types = {
            'UL_DCCH_Message', 'DL_DCCH_Message', 'UL_CCCH_Message', 'DL_CCCH_Message',
            'BCCH_DL_SCH_Message', 'BCCH_BCH_Message', 'PCCH_Message', 'MCCH_Message',
            'ul_dcch_message', 'dl_dcch_message', 'ul_ccch_message', 'dl_ccch_message',
            'message', 'criticalExtensions', 'c1'
        }
        rrc_msg = None
        nas_msg = None
        rrc_fields = packet.findall('.//field')
        for field in rrc_fields:
            if rrc_msg:
                break
            field_name = field.get('name', '')
            if field_name.startswith('lte-rrc.') and field_name.endswith('_element'):
                msg_type = field_name.replace('lte-rrc.', '').replace('_element', '')
                if (msg_type and not msg_type.endswith(('_r8', '_r9', '_r10', '_r11', '_r12', '_r13', '_r15'))
                        and msg_type not in skip_types):
                    readable = re.sub(r'([a-z])([A-Z])', r'\1 \2', msg_type)
                    readable = readable.replace('rrc', 'RRC').replace('RRC ', 'RRC')
                    rrc_msg = readable
                    break
            elif field_name.startswith('nr-rrc.') and ('_message' in field_name or '_element' in field_name):
                msg_type = field_name.replace('nr-rrc.', '').replace('_message', '').replace('_element', '')
                if (msg_type and not msg_type.endswith(('_r15', '_r16', '_r17')) and msg_type not in skip_types):
                    readable = re.sub(r'([a-z])([A-Z])', r'\1 \2', msg_type)
                    rrc_msg = f"NR-{readable}"
                    break
        if not nas_msg:
            nas_emm_fields = packet.findall('.//field[@name="nas-eps.nas_msg_emm_type"]')
            if nas_emm_fields:
                showname = nas_emm_fields[0].get('showname', '')
                match = re.search(r':\s*([^(]+)\s*\(', showname)
                if match:
                    nas_msg = match.group(1).strip()
        if not nas_msg:
            nas_esm_fields = packet.findall('.//field[@name="nas-eps.nas_msg_esm_type"]')
            if nas_esm_fields:
                showname = nas_esm_fields[0].get('showname', '')
                match = re.search(r':\s*([^(]+)\s*\(', showname)
                if match:
                    nas_msg = match.group(1).strip()
        if not nas_msg:
            nas_5gs_fields = packet.findall('.//field[@name="nas-5gs.mm.message_type"]')
            if nas_5gs_fields:
                showname = nas_5gs_fields[0].get('showname', '')
                match = re.search(r':\s*([^(]+)\s*\(', showname)
                if match:
                    nas_msg = match.group(1).strip()
        if not nas_msg:
            gsm_fields = packet.findall('.//field[@name="gsm_a.dtap.msg_gmm_type"]')
            if gsm_fields:
                showname = gsm_fields[0].get('showname', '')
                match = re.search(r':\s*([^(]+)\s*\(', showname)
                if match:
                    nas_msg = f"GSM {match.group(1).strip()}"
        if rrc_msg and nas_msg:
            return f"{rrc_msg}, {nas_msg}"
        elif rrc_msg:
            return rrc_msg
        elif nas_msg:
            return nas_msg
        else:
            return 'Unknown'

    def _normalize_field_value(self, value, field_type=None):
        if not value or str(value).strip().lower() in {'n/a', 'null', 'none', ''}:
            return '-1'
        value_str = str(value).strip()
        if field_type == 'name':
            return '1' if value_str else '0'
        elif field_type == 'showname':
            if not value_str:
                return '000'
            hash_val = abs(hash(value_str)) % 1000
            return f'{hash_val:03d}'
        elif field_type in ['size', 'pos']:
            try:
                return str(int(value_str))
            except (ValueError, TypeError):
                return '-1'
        elif field_type == 'show':
            if value_str.lower() == 'true':
                return '1'
            elif value_str.lower() == 'false':
                return '0'
            try:
                clean = value_str.replace(',', '').replace(' ', '').replace('0x', '')
                if clean.replace('-', '').replace('.', '').isdigit():
                    num = abs(float(clean))
                    return str(int(num))
            except (ValueError, TypeError):
                pass
            hash_val = abs(hash(value_str)) % 100
            return f'{hash_val:02d}'
        elif field_type in ['value', 'unmaskedvalue']:
            return value_str
        try:
            return str(int(float(value_str)))
        except (ValueError, TypeError):
            hash_val = abs(hash(value_str)) % 100
            return f'{hash_val:02d}'


    def _extract_essential_fields(self, element, packet_info):
        for child in element:
            if child.tag == 'field':
                field_name = child.get('name', '')
                if field_name.startswith(('geninfo.', 'user_dlt.', 'aww.')):
                    continue
                if field_name.startswith('frame.') and field_name != 'frame.time_relative':
                    continue
                header = self._slugify(field_name)
                field_show = child.get('show', '')
                field_value = child.get('value', '')
                if header not in self.essential_fields:
                    self._extract_essential_fields(child, packet_info)
                    continue
                if (
                    not field_show
                    and not field_value
                    and 'size' not in child.attrib
                    and 'pos' not in child.attrib
                ):
                    self._extract_essential_fields(child, packet_info)
                    continue
                field_data = []
                attrs = [
                    ('show', 'show'),
                    ('value', 'value'),
                    ('size', 'size'),
                    ('pos', 'pos')
                ]
                for attr_name, field_type in attrs:
                    if attr_name in child.attrib:
                        value = child.get(attr_name)
                        # Use special normalization for different field types
                        if attr_name == 'value':
                            # Use _convert_hex_hybrid for value attributes
                            converted = self._convert_hex_hybrid(value)
                            normalized = str(converted)
                        else:
                            normalized = self._normalize_field_value(value, field_type)
                        field_data.append(normalized)
                    else:
                        field_data.append('-1')
                if field_data:
                    packet_info[header] = field_data
            self._extract_essential_fields(child, packet_info)

    def _extract_frame_time_relative(self, packet, packet_idx):
        for proto in packet.findall('proto'):
            if proto.get('name') == 'frame':
                for field in proto.findall('.//field'):
                    if field.get('name') == 'frame.time_relative':
                        show_value = field.get('show', '')
                        if show_value:
                            try:
                                return float(show_value.split()[0])
                            except (ValueError, IndexError):
                                pass
        return packet_idx

    def _extract_packet_fields(self, packet, packet_idx):
        packet_type = self._classify_packet_type(packet)
        # Do not drop packets; keep even "other" category
        timestamp = self._extract_frame_time_relative(packet, packet_idx)
        packet_info = {
            'timestamp': timestamp,
            'message_index': packet_idx,
            'packet_type': packet_type
        }
        direction = self._get_packet_direction(packet)
        if direction is not None:
            packet_info['direction'] = direction
        info = self._extract_packet_info(packet)
        packet_info['info'] = info
        self._extract_essential_fields(packet, packet_info)
        return packet_info

    def parse_pdml(self, pdml_file):
        try:
            # Use context manager to avoid ResourceWarning
            with open(pdml_file, 'rb') as pdml_stream:
                tree = ET.parse(pdml_stream)
            root = tree.getroot()
            if root.tag == 'pdml_capture':
                packets = []
                for child in root:
                    if child.tag == 'packet' and child.get('number'):
                        nested = child.findall('packet')
                        packets.append((child.get('number'), nested[0] if nested else child))
            else:
                packets = [(str(i+1), child) for i, child in enumerate(root) if child.tag == 'packet']
            for packet_num, packet in packets:
                try:
                    packet_info = self._extract_packet_fields(packet, int(packet_num) - 1)
                    self.packets.append(packet_info)
                except Exception as e:
                    self.logger.error(f"Error processing packet {packet_num}: {e}")
            return True
        except Exception as e:
            self.logger.error(f"Error parsing PDML file: {e}")
            return False

    def generate_essential_csv(self, output_file):
        try:
            if not self.packets:
                self.logger.warning("No packet data to write")
                return False
            # Only essential fields: drop metadata columns
            headers = []
            for field in self._sorted_fields:
                headers.append(f"{field}_show")
                headers.append(f"{field}_value")
                headers.append(f"{field}_size")
                headers.append(f"{field}_pos")
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(headers)
                for packet in self.packets:
                    row = []
                    for field in self._sorted_fields:
                        field_array = packet.get(field, None)
                        if field_array and isinstance(field_array, list) and len(field_array) >= 4:
                            row.append(field_array[0])  # _show
                            row.append(field_array[1])  # _value
                            row.append(field_array[2])  # _size
                            row.append(field_array[3])  # _pos
                        elif field_array and isinstance(field_array, list) and len(field_array) >= 3:
                            row.append(field_array[0])  # _show
                            row.append(field_array[1])  # _value
                            row.append(field_array[2])  # _size
                            row.append('-1')  # _pos
                        elif field_array and isinstance(field_array, list) and len(field_array) >= 2:
                            row.append(field_array[0])  # _show
                            row.append(field_array[1])  # _value
                            row.append('-1')  # _size
                            row.append('-1')  # _pos
                        elif field_array and isinstance(field_array, list) and len(field_array) >= 1:
                            row.append(field_array[0])  # _show
                            row.append('-1')  # _value
                            row.append('-1')  # _size
                            row.append('-1')  # _pos
                        else:
                            row.append('-1')  # _show
                            row.append('-1')  # _value
                            row.append('-1')  # _size
                            row.append('-1')  # _pos
                    
                    writer.writerow(row)
            self.logger.info(f"Wrote {len(self.packets)} packets to {output_file}")
            self.logger.info(f"Included all {len(self.essential_fields)} essential fields from nas_rrc_headers_ai.py")
            return True
        except Exception as e:
            self.logger.error(f"Error writing CSV: {e}")
            return False

    def convert_pdml_to_csv(self, pdml_file, output_dir=None, custom_filename=None):
        if not self.parse_pdml(pdml_file):
            return False
        base_path = Path(pdml_file)
        if output_dir is None:
            output_dir = self.output_dir
        else:
            output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        filename = custom_filename if custom_filename else self._normalize_filename(base_path.stem)
        essential_csv = output_dir / f"{filename}_essential.csv"
        if self.generate_essential_csv(essential_csv):
            self.logger.info(f"Successfully generated essential fields CSV: {essential_csv}")
            self.logger.info(f"Output directory: {output_dir}")
            return True
        else:
            self.logger.error("Failed to generate essential fields CSV")
            return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    xml_files = list(Path('.').glob('*.xml'))
    if xml_files:
        preprocessor = NASRRCPreprocessor()
        if preprocessor.parse_pdml(xml_files[0]):
            base_path = Path(xml_files[0])
            output_dir = Path("dataset_csv_ai")
            output_dir.mkdir(parents=True, exist_ok=True)
            filename = preprocessor._normalize_filename(base_path.stem)
            essential_csv = output_dir / f"{filename}_essential.csv"
            preprocessor.generate_essential_csv(essential_csv)
    else:
        logging.warning("No XML files found")
