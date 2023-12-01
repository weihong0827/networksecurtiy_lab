import binascii
import struct



def KSA(key):
    S = list(range(256))
    j = 0
    for i in range (256):
        j = (j+S[i]+key[i%len(key)])%256
        S[i],S[j] = S[j],S[i]
    

    # Add KSA implementation Here
    
    return S

def PRGA(S):
    K = 0
    # Add PRGA implementation here
    i = 0
    j = 0
    while True:
        i = (i+1)%256
        j = (j+S[i])%256
        S[i],S[j] = S[j],S[i]
        K = S[(S[i]+ S[j])%256]

        yield K

def RC4(key):
    S = KSA(key)
    return PRGA(S)
def test_RC4(key, ciphertext):
    key = binascii.unhexlify(key)
    ciphertext = binascii.unhexlify(ciphertext)

    keystream = RC4(key)

    plaintext = "".join('{:02X}'.format(c ^ next(keystream)) for c in ciphertext)

    return plaintext

if __name__ == '__main__':
    # RC4 algorithm please refer to http://en.wikipedia.org/wiki/RC4

    ## key = a list of integer, each integer 8 bits (0 ~ 255)
    ## ciphertext = a list of integer, each integer 8 bits (0 ~ 255)
    ## binascii.unhexlify() is a useful function to convert from Hex string to integer list

    ## Use RC4 to generate keystream
    test_cases = [

        ('1A2B3C', '00112233'),

        ('000000', '00112233'),

        ('012345', '00112233')

    ]
    test_results = {test_case: test_RC4(*test_case) for test_case in test_cases}

    print(test_results)
    
    #     Several test cases: (to test RC4 implementation only)
    #     1. key = '1A2B3C', cipertext = '00112233' -> plaintext = '0F6D13BC'
    #     2. key = '000000', cipertext = '00112233' -> plaintext = 'DE09AB72'
    #     3. key = '012345', cipertext = '00112233' -> plaintext = '6F914F8F'
    data ='2ce5f9e9d858976bf343584be117052403179d3b1aae6718a0127eded821aebbb87e1da8ee9a4774742f83269a3d7eae6efad65b6bb6'
    wep_key = '1F1F1F1F1F'
    IV = "e8c831"
    expected_ICV = "0x07532477"

    print(f"Cracking packet with:\nencrypted data:{data}\nwep key:{wep_key}\nIV:{IV}\nThe expected ICV value:{expected_ICV}")
    
    rc4_key = IV + wep_key
    
    decrypted_data = test_RC4(rc4_key, data)

    
    
    # Calculate the CRC32 of the decrypted data
    crcle = binascii.crc32(bytes.fromhex(decrypted_data)) & 0xffffffff
    crc = struct.pack('<L', crcle)
   
    crc_plaintext = binascii.hexlify(crc).decode('utf-8')
   
    
    ## Check ICV
    concat_plaintext = decrypted_data+crc_plaintext
    new_cipher = test_RC4(rc4_key,concat_plaintext)
    print("==================Cracking result========================")
    print(f"The plain text is {decrypted_data}")
    print(f"The ICV for the encrypted text is {new_cipher[-8:]}")


    
   