#Can only encrypt, Lzss is not working .
import os
from struct import unpack, pack

scrpath = 'scr'

def LzssCompress(uncompr):
    compr = bytearray()
    win = bytearray(0x1000)
    iWin = 0xfee
    iSrc = 0
    
    while iSrc < len(uncompr):
        code = 0
        for i in range(8):
            if iSrc >= len(uncompr):
                break
            
            found = False
            pos = 0
            count = 0
            
            for j in range(0x1000):
                if uncompr[iSrc] == win[(iWin - j) & 0xfff]:
                    found = True
                    pos = (iWin - j) & 0xfff
                    count = 1
                    while iSrc + count < len(uncompr) and count < 18:
                        if uncompr[iSrc + count] == win[(pos + count) & 0xfff]:
                            count += 1
                        else:
                            break
                    break
            
            if found and count >= 3:
                compr.append(pos & 0xff)
                compr.append(((pos >> 4) & 0xf0) | (count - 3))
                iSrc += count
            else:
                code |= 1 << i
                compr.append(uncompr[iSrc])
                win[iWin] = uncompr[iSrc]
                iWin = (iWin + 1) & 0xfff
                iSrc += 1
        
        if code != 0xff:
            compr.append(code)
    
    return bytes(compr)

def Encrypt(stm):
    for i in range(len(stm)):
        stm[i] ^= i & 0xff

# Iterate over all files in the specified directory
for f in os.listdir(scrpath):
    with open(os.path.join(scrpath, f), 'rb+') as fs:
        # Read the header
        header_data = fs.read(0x3c)
        magic, is_compr, unclen, comprlen, inst_count, str_count, inst_len, str_len = unpack('16s4xiII4xII4xII4x', header_data)
        
        # Move to data offset and read the uncompressed data
        fs.seek(0x1c8)
        buff = bytearray(fs.read(unclen))
        
        # Encrypt the data
        Encrypt(buff)
        
        if len(buff) < unclen:
            is_compr = -1
            compr_buff = LzssCompress(buff)
            Encrypt(compr_buff)
            fs.seek(0x1c8)
            fs.write(compr_buff)
            comprlen = len(compr_buff)
        else:
            is_compr = 0
            fs.seek(0x1c8)
            fs.write(buff)
            comprlen = unclen
        
        # Update and write the header back
        fs.seek(0)
        header = pack('16s4xiII4xII4xII4x', magic, is_compr, unclen, comprlen, inst_count, str_count, inst_len, str_len)
        fs.write(header)
