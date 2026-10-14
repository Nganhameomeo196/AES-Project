"""Generate synthetic RGB images to show ECB's repeated-block pattern.

Writes portable PPM files without external dependencies. Not an attack on AES.
"""
from pathlib import Path
import struct
import zlib
from src.modes import ecb_encrypt, cbc_encrypt


def write_png(path, rgb, width, height):
    """Write 8-bit RGB PNG with the standard library."""
    def chunk(tag, payload):
        return struct.pack(">I", len(payload)) + tag + payload + struct.pack(">I", zlib.crc32(tag + payload) & 0xffffffff)
    stride = width * 3
    scanlines = b"".join(b"\x00" + rgb[i:i + stride] for i in range(0, len(rgb), stride))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(scanlines)) + chunk(b"IEND", b""))


def run(width=192, height=128, output='results'):
    if width < 16 or height < 16 or (width*height*3) % 16:
        raise ValueError('Dimensions must produce at least one AES block and block-aligned RGB data')
    folder=Path(output)
    folder.mkdir(parents=True,exist_ok=True)
    pixels=bytearray()
    for y in range(height):
        for x in range(width):
            square=((x//24)+(y//24))%2
            pixels.extend((255,255,255) if square else (20,40,80))
    key=bytes(range(16))
    iv=bytes(range(16,32))
    original=bytes(pixels)
    # PKCS7 adds a final block; crop to original image length for visualization only.
    images={'original':original,'ecb':ecb_encrypt(original,key)[:len(original)],
            'cbc':cbc_encrypt(original,key,iv)[:len(original)]}
    for name,data in images.items():
        path=folder/f'pattern_{name}.ppm'
        path.write_bytes(f'P6\n{width} {height}\n255\n'.encode()+data)
        write_png(folder / f"pattern_{name}.png", data, width, height)
        print('Saved',path, "and PNG")
    return images

if __name__=='__main__':run()
