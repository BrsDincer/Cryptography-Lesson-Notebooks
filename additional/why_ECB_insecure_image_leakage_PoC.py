"""
The fundamental weakness of the AES-ECB encryption mode is that identical plaintext blocks are converted into identical ciphertext blocks.
This feature leads to significant information leakage, especially when used on images or repetitive data.
Patterns in the image are still visible in the encrypted data through the block structure.

The code provides concrete visuals showing why ECB mode is unsafe in practice.
"""

import numpy as np
from PIL import Image
import os,hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes

BLOCKSIZE = 16 # AES block size in bytes (and we'll align pixels to this)
KEY = os.urandom(BLOCKSIZE)
IMAGEPATH = os.path.join(os.getcwd(),"samples","lock_image.jpg")
SAVEPATH = os.path.join(os.getcwd(),"samples","ECB_encrypted_lock_image.jpg")

def LoadGrayscale(path:str)->np.ndarray:
    """
    Load an image file as uint8 grayscale (H, W).
    """
    grayIMG = Image.open(path).convert("L") # grayscale
    arrayIMG = np.array(grayIMG,dtype=np.uint8)
    return arrayIMG

def PaddingImageBlock(image:np.ndarray,blockSize:int=BLOCKSIZE)->np.ndarray:
    """
    Pad image on bottom/right with zeros so that width*height is a multiple of 16.
    Additionally, pad width to a multiple of 16 so that 1 block == 16 horizontal pixels.

    Since each pixel of the image = 1 byte, 1 block = 16 pixels.
    """
    height,width = image.shape
    newWidth = ((width+blockSize-1)//blockSize)*blockSize
    newHeight = ((height+1)//1)*1 # keep rows as-is (pixel = 1 byte)
    # Ensure total bytes multiple of 16
    totalBytes = newWidth*newHeight
    if totalBytes % blockSize != 0:
        # make height multiple of block if needed
        newHeight = ((newHeight+blockSize-1)//blockSize)*blockSize
    padHeight = max(0,newHeight-height)
    padWidth = max(0,newWidth-width)
    if padHeight or padWidth:
        padded = np.zeros((newHeight,newWidth),dtype=np.uint8)
        padded[:height,:width] = image
        return padded
    return image

def AESEncryptECB(bytesIN:bytes,key:bytes)->bytes:
    AESEngine = Cipher(
        algorithm=algorithms.AES(key),
        mode=modes.ECB(),
        backend=default_backend()
    )
    encryptor = AESEngine.encryptor()
    cipher = encryptor.update(bytesIN)+encryptor.finalize()
    return cipher

def BlocksToToneImage(cipherBytes:bytes,height:int,width:int,blockSize:int=BLOCKSIZE)->np.ndarray:
    """
    Map each 16-byte block to a grayscale tone (0..255).
    Identical blocks -> identical tone. Returns (H, W) uint8 image.
    """
    assert len(cipherBytes) == height*width,"Ciphertext length must equal H*W for 1 byte per pixel."
    blockNumbers = len(cipherBytes)//blockSize
    tones = np.zeros(blockNumbers,dtype=np.uint8)
    for idx in range(blockNumbers):
        bulk = cipherBytes[idx*blockSize:(idx+1)*blockSize]
        # Deterministic mapping: first byte of SHA-256 hash
        tones[idx] = hashlib.sha256(bulk).digest()[0]
    # It copies each tone 16 times in succession, producing a sequence that matches the original block size.
    expanded = np.repeat(tones,blockSize).astype(np.uint8) # Since each pixel of the image = 1 byte, 1 block = 16 pixels.
    return expanded.reshape((height,width))

def SaveImageU8(path:str,arrayIMG:np.ndarray)->None:
    Image.fromarray(arrayIMG,mode="L").save(path)


imageArray = LoadGrayscale(IMAGEPATH)
imagePadded = PaddingImageBlock(imageArray,BLOCKSIZE)
height,width = imagePadded.shape

# It converts a matrix to a one-dimensional array.
imageFlattenBytes = imagePadded.flatten().tobytes() # Padded 2D image matrix (NumPy array of dimensions H × W).
# The AES algorithm works with a raw byte array, not a 2D image.
imageEncryptedECB = AESEncryptECB(bytesIN=imageFlattenBytes,key=KEY)
toneECB = BlocksToToneImage(cipherBytes=imageEncryptedECB,height=height,width=width,blockSize=BLOCKSIZE)

SaveImageU8(path=SAVEPATH,arrayIMG=toneECB)

