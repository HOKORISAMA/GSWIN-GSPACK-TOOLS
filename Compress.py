#WORK IN PROGRESS

import os
from struct import pack

def LzssCompress(data):
    compressed = bytearray()
    window = bytearray(0x1000)
    window_pos = 0xfee
    i = 0
    while i < len(data):
        code_byte = 0
        code_pos = len(compressed)
        compressed.append(0)
        
        for bit in range(8):
            if i >= len(data):
                break
            
            # Search for a match in the window
            best_len = 2
            best_pos = 0
            for pos in range(0x1000):
                length = 0
                while (length < 18 and 
                       i + length < len(data) and 
                       data[i + length] == window[(pos + length) & 0xfff]):
                    length += 1
                if length > best_len:
                    best_len = length
                    best_pos = pos
                    if best_len == 18:
                        break
            
            if best_len > 2:
                # Encode as (position, length) pair
                pos_high = (best_pos >> 8) & 0xF
                pos_low = best_pos & 0xFF
                length = (best_len - 3) & 0xF
                compressed.append(pos_low)
                compressed.append((pos_high << 4) | length)
                
                for j in range(best_len):
                    window[window_pos] = data[i]
                    window_pos = (window_pos + 1) & 0xfff
                    i += 1
            else:
                # Encode as literal byte
                code_byte |= (1 << bit)
                compressed.append(data[i])
                window[window_pos] = data[i]
                window_pos = (window_pos + 1) & 0xfff
                i += 1
        
        compressed[code_pos] = code_byte
    
    return compressed

def Encrypt(stm):
    for i in range(len(stm)):
        stm[i] ^= i & 0xFF

scrpath = 'scr'
for f in os.listdir(scrpath):
    with open(os.path.join(scrpath, f), 'rb+') as fs:
        fs.seek(0x1c8)
        data = fs.read()
        
        # Compress the data
        compressed = LzssCompress(data)
        
        # Encrypt the compressed data
        Encrypt(compressed)
        
        # Prepare the header
        header = pack('16s4xiII4xII4xII4x',
                      b'Scw5.x\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',  # Magic bytes
                      -1,  # is_compr (compressed)
                      len(data),  # unclen
                      len(compressed),  # comprlen
                      159,  # inst_count
                      138,  # str_count
                      11028,  # inst_len
                      6475)  # str_len
        
        # Write the packed file
        fs.seek(0)
        fs.write(header)
        fs.seek(0x1c8)
        fs.write(compressed)
        fs.truncate()

print("Packing completed.")
