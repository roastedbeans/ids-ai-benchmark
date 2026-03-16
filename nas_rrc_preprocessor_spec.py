#!/usr/bin/env python3
# coding: utf8

import xml.etree.ElementTree as ET
import csv
import re
import logging
from pathlib import Path
from nas_rrc_headers_spec import nas_rrc_headers_spec


class NASRRCPreprocessor:
    def __init__(self, logger=None, exclude_parent_headers=True):
        self.logger = logger or logging.getLogger(__name__)
        self.packets = []
        self.exclude_parent_headers = exclude_parent_headers

        # Base output locations for SPEC analysis (mirrors AI path separation)
        self.base_dir = Path("/sdcard/Documents/MODI/spec")
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

        # Define parent/container header patterns to exclude
        self.parent_header_patterns = [
            '_element',           # Container elements
            '_container',         # Container fields
            'c1',                 # Choice containers
            'criticalExtensions', # Extension containers
        ]

        # Filter headers based on exclusion patterns
        if self.exclude_parent_headers:
            filtered_headers = []
            for header in nas_rrc_headers_spec:
                # Skip headers that match parent/container patterns
                if not any(pattern in header for pattern in self.parent_header_patterns):
                    filtered_headers.append(header)
            self.essential_fields = set(self._slugify(h) for h in filtered_headers)
            self.logger.info(f"Excluded {len(nas_rrc_headers_spec) - len(filtered_headers)} parent/container headers")
        else:
            # Use all headers (original behavior)
            self.essential_fields = set(self._slugify(h) for h in nas_rrc_headers_spec)

        self.logger.info(f"Using {len(self.essential_fields)} essential fields for extraction")

    def _slugify(self, text):
        """Convert text to slug format with underscores"""
        if not text:
            return ""
        text = re.sub(r'[^\w\s-]', '_', text)
        text = re.sub(r'[\s_]+', '_', text)
        text = text.strip('_')
        return text.lower()

    def _classify_packet_type(self, packet):
        """Classify packet as NAS, RRC, or NAS+RRC based on protocol"""
        protos = packet.findall('.//proto')
        proto_names = [proto.get('name', '').lower() for proto in protos]

        has_nas = 'nas-eps' in proto_names or 'nas-5gs' in proto_names
        has_rrc = any('rrc' in name for name in proto_names)

        if has_nas and has_rrc:
            return 'nas+rrc'
        elif has_nas:
            return 'nas'
        elif has_rrc:
            return 'rrc'
        return 'other'

    def _get_packet_direction(self, packet):
        """Determine packet direction from RRC message types or GSM TAP (0=DL, 1=UL)"""
        # Downlink message fields (based on actual PDML field names)
        dl_fields = [
            'lte-rrc.DL_DCCH_Message_element',
            'lte-rrc.DL_CCCH_Message_element',
            'lte-rrc.BCCH_DL_SCH_Message_element',
            'lte-rrc.BCCH_BCH_Message_element',
            'nr-rrc.dl_dcch_message_message',
            'nr-rrc.dl_ccch_message_message',
        ]

        # Uplink message fields (based on actual PDML field names)
        ul_fields = [
            'lte-rrc.UL_DCCH_Message_element',
            'lte-rrc.UL_CCCH_Message_element',
            'nr-rrc.ul_dcch_message_message',
            'nr-rrc.ul_ccch_message_message',
        ]

        # First, check RRC direction (takes precedence for nested protocols)
        for field_name in dl_fields:
            if packet.find(f'.//field[@name="{field_name}"]') is not None:
                return '0'

        for field_name in ul_fields:
            if packet.find(f'.//field[@name="{field_name}"]') is not None:
                return '1'

        # If no RRC direction found, check GSM TAP uplink field for standalone packets
        gsmtap_uplink = packet.find('.//field[@name="gsmtap.uplink"]')
        if gsmtap_uplink is not None:
            uplink_value = gsmtap_uplink.get('show', '')
            if uplink_value == '0':
                return '0'  # Downlink
            elif uplink_value == '1':
                return '1'  # Uplink

        return None

    def _extract_packet_info(self, packet):
        """Extract human-readable packet info (like Wireshark's Info column)"""
        # Define wrapper/generic message types to skip
        skip_types = {
            'UL_DCCH_Message', 'DL_DCCH_Message', 'UL_CCCH_Message', 'DL_CCCH_Message',
            'BCCH_DL_SCH_Message', 'BCCH_BCH_Message', 'PCCH_Message', 'MCCH_Message',
            'ul_dcch_message', 'dl_dcch_message', 'ul_ccch_message', 'dl_ccch_message',
            'message', 'criticalExtensions', 'c1'
        }

        rrc_msg = None
        nas_msg = None

        # Extract first RRC message type
        rrc_fields = packet.findall('.//field')
        for field in rrc_fields:
            if rrc_msg:
                break
            field_name = field.get('name', '')

            # Match LTE-RRC message types
            if field_name.startswith('lte-rrc.') and field_name.endswith('_element'):
                msg_type = field_name.replace('lte-rrc.', '').replace('_element', '')
                if (msg_type and
                    not msg_type.endswith(('_r8', '_r9', '_r10', '_r11', '_r12', '_r13', '_r15')) and
                    msg_type not in skip_types):
                    # Convert camelCase to readable format
                    readable = re.sub(r'([a-z])([A-Z])', r'\1 \2', msg_type)
                    readable = readable.replace('rrc', 'RRC').replace('RRC ', 'RRC')
                    rrc_msg = readable
                    break

            # Match NR-RRC message types
            elif field_name.startswith('nr-rrc.') and ('_message' in field_name or '_element' in field_name):
                msg_type = field_name.replace('nr-rrc.', '').replace('_message', '').replace('_element', '')
                if (msg_type and
                    not msg_type.endswith(('_r15', '_r16', '_r17')) and
                    msg_type not in skip_types):
                    readable = re.sub(r'([a-z])([A-Z])', r'\1 \2', msg_type)
                    rrc_msg = f"NR-{readable}"
                    break

        # Extract first NAS-EPS EMM message type
        if not nas_msg:
            nas_emm_fields = packet.findall('.//field[@name="nas-eps.nas_msg_emm_type"]')
            if nas_emm_fields:
                showname = nas_emm_fields[0].get('showname', '')
                match = re.search(r':\s*([^(]+)\s*\(', showname)
                if match:
                    nas_msg = match.group(1).strip()

        # Extract first NAS-EPS ESM message type if no EMM found
        if not nas_msg:
            nas_esm_fields = packet.findall('.//field[@name="nas-eps.nas_msg_esm_type"]')
            if nas_esm_fields:
                showname = nas_esm_fields[0].get('showname', '')
                match = re.search(r':\s*([^(]+)\s*\(', showname)
                if match:
                    nas_msg = match.group(1).strip()

        # Extract first NAS-5GS message type if no EPS found
        if not nas_msg:
            nas_5gs_fields = packet.findall('.//field[@name="nas-5gs.mm.message_type"]')
            if nas_5gs_fields:
                showname = nas_5gs_fields[0].get('showname', '')
                match = re.search(r':\s*([^(]+)\s*\(', showname)
                if match:
                    nas_msg = match.group(1).strip()

        # Build info string based on what was found
        if rrc_msg and nas_msg:
            return f"{rrc_msg}, {nas_msg}"
        elif rrc_msg:
            return rrc_msg
        elif nas_msg:
            return nas_msg
        else:
            return 'Unknown'

    def _normalize_field_value(self, value, field_type=None):
        """Normalize field value to numeric representation"""
        if not value or str(value).strip().lower() in {'n/a', 'null', 'none', ''}:
            return '-1'

        value_str = str(value).strip()

        # Handle different attribute types
        if field_type == 'name':
            # Binary: presence indicator
            return '1' if value_str else '0'

        elif field_type == 'showname':
            # Hash descriptive text to 3 digits
            if not value_str:
                return '000'
            hash_val = sum(ord(c) * (i + 1) for i, c in enumerate(value_str)) % 1000
            return f'{hash_val:03d}'

        elif field_type in ['size', 'pos']:
            # Keep numeric position/size values
            try:
                return str(int(value_str))
            except (ValueError, TypeError):
                return '-1'

        elif field_type == 'show':
            # Normalize show values to numeric
            if value_str.lower() == 'true':
                return '1'
            elif value_str.lower() == 'false':
                return '0'

            # Try to extract numeric value
            try:
                # Remove common separators
                clean = value_str.replace(',', '').replace(' ', '').replace('0x', '')
                if clean.replace('-', '').replace('.', '').isdigit():
                    num = abs(float(clean))
                    return str(int(num))
            except (ValueError, TypeError):
                pass

            # Hash text to 2 digits
            hash_val = sum(ord(c) for c in value_str) % 100
            return f'{hash_val:02d}'

        elif field_type in ['value', 'unmaskedvalue']:
            # Preserve actual hex/binary values as-is
            return value_str

        # Default: try numeric, else hash
        try:
            return str(int(float(value_str)))
        except (ValueError, TypeError):
            hash_val = sum(ord(c) for c in value_str) % 100
            return f'{hash_val:02d}'

    def _extract_essential_fields(self, element, packet_info):
        """Extract only essential fields from the packet"""
        for child in element:
            if child.tag == 'field':
                field_name = child.get('name', '')

                # Skip unwanted protocols
                if field_name.startswith(('geninfo.', 'frame.', 'user_dlt.', 'aww.')):
                    continue

                # Convert field name to slug format for comparison
                header = self._slugify(field_name)

                # Only process if this field is in our essential fields list
                if header not in self.essential_fields:
                    self._extract_essential_fields(child, packet_info)
                    continue

                # Get field values
                field_show = child.get('show', '')
                field_value = child.get('value', '')

                # Skip if no meaningful content
                if not field_show and not field_value:
                    self._extract_essential_fields(child, packet_info)
                    continue

                # Store field with normalized values (only _show and _value for optimization)
                field_data = []
                attrs = [
                    ('show', 'show'),
                    ('value', 'value')
                ]

                for attr_name, field_type in attrs:
                    if attr_name in child.attrib:
                        value = child.get(attr_name)
                        normalized = self._normalize_field_value(value, field_type)
                        field_data.append(normalized)

                if field_data:
                    packet_info[header] = field_data

            # Recurse into child elements
            self._extract_essential_fields(child, packet_info)

    def _extract_packet_fields(self, packet, packet_idx):
        """Extract essential fields from a single packet"""
        packet_type = self._classify_packet_type(packet)

        if packet_type == 'other':
            return None

        packet_info = {
            'timestamp': packet_idx,
            'message_index': packet_idx,
            'packet_type': packet_type
        }

        # Get direction
        direction = self._get_packet_direction(packet)
        if direction is not None:
            packet_info['direction'] = direction

        # Extract packet info (message type)
        info = self._extract_packet_info(packet)
        packet_info['info'] = info

        # Extract only essential fields
        self._extract_essential_fields(packet, packet_info)

        return packet_info

    def parse_pdml(self, pdml_file):
        """Parse PDML XML file and extract essential field data"""
        try:
            tree = ET.parse(pdml_file)
            root = tree.getroot()

            # Handle both ws_dissector and tshark formats
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
                    if packet_info:
                        self.packets.append(packet_info)
                except Exception as e:
                    self.logger.error(f"Error processing packet {packet_num}: {e}")

            return True
        except Exception as e:
            self.logger.error(f"Error parsing PDML file: {e}")
            return False

    def generate_essential_csv(self, output_file):
        """Generate CSV with ALL essential fields from nas_rrc_headers, filling missing fields with -1"""
        try:
            if not self.packets:
                self.logger.warning("No packet data to write")
                return False

            # Create headers with metadata first, then ALL essential fields
            headers = ['timestamp', 'message_index', 'packet_type', 'direction', 'info']

            # Add ALL essential field columns (_show and _value for each field)
            # This ensures consistent column structure regardless of which fields have data
            for field in sorted(self.essential_fields):
                headers.append(f"{field}_show")
                headers.append(f"{field}_value")

            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(headers)

                for packet in self.packets:
                    row = [
                        packet.get('timestamp', '-1'),
                        packet.get('message_index', '-1'),
                        packet.get('packet_type', 'unknown'),
                        packet.get('direction', '-1'),
                        packet.get('info', 'Unknown')
                    ]

                    # Add ALL essential field data, filling with -1 if missing
                    for field in sorted(self.essential_fields):
                        field_array = packet.get(field, None)

                        if field_array and isinstance(field_array, list) and len(field_array) >= 2:
                            # Field has both _show and _value
                            row.append(field_array[0])  # _show
                            row.append(field_array[1])  # _value
                        elif field_array and isinstance(field_array, list) and len(field_array) >= 1:
                            # Field has at least _show
                            row.append(field_array[0])  # _show
                            row.append('-1')  # _value (missing)
                        else:
                            # Field is completely missing
                            row.append('-1')  # _show
                            row.append('-1')  # _value

                    writer.writerow(row)

            self.logger.info(f"Wrote {len(self.packets)} packets to {output_file}")
            self.logger.info(f"Included all {len(self.essential_fields)} essential fields from nas_rrc_headers.py")
            return True
        except Exception as e:
            self.logger.error(f"Error writing CSV: {e}")
            return False

    def convert_pdml_to_csv(self, pdml_file, output_dir=None, custom_filename=None):
        """Convert PDML to single essential fields CSV with all headers from nas_rrc_headers.py"""
        if not self.parse_pdml(pdml_file):
            return False

        base_path = Path(pdml_file)

        # Default to SPEC output folder if not provided
        if output_dir is None:
            output_dir = self.output_dir
        else:
            output_dir = Path(output_dir)

        output_dir.mkdir(parents=True, exist_ok=True)

        # Use custom filename if provided, otherwise use XML stem
        filename = custom_filename if custom_filename else base_path.stem

        # Generate single essential fields CSV
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
        preprocessor.convert_pdml_to_csv(xml_files[0])
    else:
        logging.warning("No XML files found")
