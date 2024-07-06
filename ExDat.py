#can extract .pak and .dat archives.
import io
import os
import struct
import argparse

class MemoryStream:
    def __init__(self, data):
        self.stream = io.BytesIO(data)
    
    def read(self, size=-1):
        return self.stream.read(size)
    
    def seek(self, offset, whence=io.SEEK_SET):
        self.stream.seek(offset, whence)

class ArcFile:
    def __init__(self, arc_view, archive_format, dir_entries):
        self.arc_view = arc_view
        self.archive_format = archive_format
        self.dir_entries = dir_entries

class LzssReader:
    def __init__(self, input_stream, input_length, output_length):
        self.input_stream = input_stream
        self.output = bytearray(output_length)
        self.size = input_length
        self.frame_size = 0x1000
        self.frame_init_pos = 0xfee

    def unpack(self):
        dst = 0
        frame = bytearray(self.frame_size)
        frame_pos = self.frame_init_pos
        frame_mask = self.frame_size - 1
        remaining = self.size

        while remaining > 0:
            ctl = ord(self.input_stream.read(1))
            remaining -= 1
            bit = 1
            while bit < 0x100:
                if dst >= len(self.output):
                    return
                if ctl & bit:
                    b = ord(self.input_stream.read(1))
                    remaining -= 1
                    frame[frame_pos] = b
                    frame_pos = (frame_pos + 1) & frame_mask
                    self.output[dst] = b
                    dst += 1
                else:
                    if remaining < 2:
                        return
                    lo = ord(self.input_stream.read(1))
                    hi = ord(self.input_stream.read(1))
                    remaining -= 2
                    offset = (hi & 0xf0) << 4 | lo
                    count = 3 + (hi & 0xF)
                    for _ in range(count):
                        if dst >= len(self.output):
                            break
                        v = frame[offset]
                        offset = (offset + 1) & frame_mask
                        frame[frame_pos] = v
                        frame_pos = (frame_pos + 1) & frame_mask
                        self.output[dst] = v
                        dst += 1
                bit <<= 1

class PakOpener:
    def __init__(self):
        self.extensions = ["pak", "dat", "pa_"]
        self.signatures = [0x61746144, 0x61507347]

    def try_open(self, arc_view):
        data = arc_view.data
        if not (data.startswith(b"DataPack5") or 
                data.startswith(b"GsPack5") or 
                data.startswith(b"GsPack4")):
            return None
        
        version_minor = struct.unpack('<H', data[0x30:0x32])[0]
        version_major = struct.unpack('<H', data[0x32:0x34])[0]
        index_size = struct.unpack('<I', data[0x34:0x38])[0]
        count = struct.unpack('<i', data[0x3c:0x40])[0]
        is_encrypted = struct.unpack('<I', data[0x38:0x3c])[0]
        data_offset = struct.unpack('<I', data[0x40:0x44])[0]
        index_offset = struct.unpack('<i', data[0x44:0x48])[0]
        entry_size = 0x48 if version_major < 5 else 0x68
        unpacked_size = count * entry_size
        
        if index_size != 0:
            packed_index = bytearray(data[index_offset:index_offset + index_size])
            if len(packed_index) != index_size:
                return None
            if is_encrypted & 1:
                for i in range(len(packed_index)):
                    packed_index[i] = (packed_index[i] ^ i) & 0xFF
            stream = MemoryStream(packed_index)
            reader = LzssReader(stream, len(packed_index), unpacked_size)
            reader.unpack()
            index = reader.output
        else:
            index = data[index_offset:index_offset + unpacked_size]
        
        index_offset = 0
        dir_entries = []
        for i in range(count):
            name = index[index_offset:index_offset + 0x40].split(b'\0', 1)[0].decode('ascii')
            if name:
                entry = {
                    'Name': name,
                    'Offset': data_offset + struct.unpack('<I', index[index_offset + 0x40:index_offset + 0x44])[0],
                    'Size': struct.unpack('<I', index[index_offset + 0x44:index_offset + 0x48])[0]
                }
                dir_entries.append(entry)
            index_offset += entry_size
        
        return ArcFile(arc_view, self, dir_entries)

    def open_entry(self, arc, entry):
        return arc.arc_view.data[entry['Offset']:entry['Offset'] + entry['Size']]

class ArcView:
    def __init__(self, file_path):
        self.file_path = file_path
        with open(file_path, 'rb') as f:
            self.data = f.read()
    
    @property
    def name(self):
        return os.path.basename(self.file_path)

def extract_archive(file_path, output_dir):
    arc_view = ArcView(file_path)
    pak_opener = PakOpener()
    arc_file = pak_opener.try_open(arc_view)
    
    if not arc_file:
        print(f"Failed to open archive: {file_path}")
        return
    
    for entry in arc_file.dir_entries:
        entry_data = pak_opener.open_entry(arc_file, entry)
        output_file_path = os.path.join(output_dir, entry['Name'])
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        with open(output_file_path, 'wb') as f:
            f.write(entry_data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract GsPack resource archives")
    parser.add_argument("archive", help="Path to the archive file")
    parser.add_argument("output_dir", help="Directory to extract files to")
    args = parser.parse_args()

    extract_archive(args.archive, args.output_dir)
