import cv2
import numpy as np
import base64
import qrcode
import os
import zxing
import matplotlib.pyplot as plt
from scipy.fftpack import dct, idct
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Constants for file paths
PRIVATE_KEY_FILE_PATH = "recipient_private_key.pem"
PUBLIC_KEY_FILE_PATH = "recipient_public_key.pem"

# Function to convert base64 encoding back to an image
def base64_to_image(base64_str, output_path):
    image_bytes = base64.b64decode(base64_str)
    image_nparr = np.frombuffer(image_bytes, np.uint8)
    image = cv2.imdecode(image_nparr, cv2.IMREAD_COLOR)
    cv2.imwrite(output_path, image)
    return output_path

# Function to convert an image to base64 encoding
def image_to_base64(img_path, resize_dim=(25, 25)):

    image = cv2.imread(img_path)
    image_resized = cv2.resize(image, resize_dim)

    # Convert the image to base64
    _, buffer = cv2.imencode('.jpg', image_resized)
    image_base64 = base64.b64encode(buffer).decode('utf-8')

    return image_base64

# Function to generate an RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Function to generate an RSA key pair and save to disk
def generate_and_save_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Save private key to file
    with open(PRIVATE_KEY_FILE_PATH, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key to file
    with open(PUBLIC_KEY_FILE_PATH, "wb") as key_file:
        key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key

def load_rsa_key_pair_from_disk():
    # Load private key from file
    with open(PRIVATE_KEY_FILE_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Load public key from file
    with open(PUBLIC_KEY_FILE_PATH, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    return private_key, public_key

# Function to encrypt a message with the recipient's public key
def encrypt_message(message, recipient_public_key):
    ciphertext = recipient_public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')

# Function to create a QR code from a message
def generate_qr_code(message, filename):
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(message)
    qr.make(fit=True)
    qr_img_path = filename
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_img.save(qr_img_path)
    return qr_img_path

# function to embed the image within the QR code
def generate_qr_code_with_image(message, image_path, filename):
    image_base64 = image_to_base64(image_path)
    combined_data = image_base64 + "|||" + message  # Use a separator to differentiate the image and message
    qr_img_path = generate_qr_code(combined_data, filename)
    qr_img = plt.imread(qr_img_path)
    plt.imshow(qr_img)
    plt.show()
    return qr_img_path

def decode_qr_with_zxing(image_path):
    reader = zxing.BarCodeReader()
    barcode = reader.decode(image_path)
    if barcode is not None:
        return barcode.raw
    return None

# function to extract the image and message from the QR code
def decode_qr_code_with_image(filename):
    decoded_data = decode_qr_with_zxing(filename)
    # print(decoded_data.count("|||"))
    if "|||" not in decoded_data:
        raise ValueError("The decoded data does not contain the expected separator.")
    image_base64, encrypted_message = decoded_data.split("|||")  # Use the separator to split the data
    image_path = base64_to_image(image_base64, "extracted_watermark_image.png")
    return image_path, encrypted_message

# Function to decrypt a message with the recipient's private key
def decrypt_message(encrypted_message_base64, recipient_private_key):
    try:
        # Decode base64 to Unicode string
        encrypted_message_unicode = base64.b64decode(encrypted_message_base64).decode('utf-8')
    except Exception as e:
        print("Error during base64 decoding:", e)
        raise

    ciphertext = encrypted_message_unicode.encode('utf-8')  # Convert Unicode to bytes

    plaintext = recipient_private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext.decode('utf-8')

#to convert the different types into binary
def messageToBinary(message):
  if (isinstance(message, str)):
    return ''.join([format(ord(i),'08b') for i in message])
  elif (isinstance(message, bytes) or isinstance(message, np.ndarray)):
    return [format(i,'08b') for i in message]
  elif (isinstance(message, int) or isinstance(message, np.uint8)):
    return format(message,'08b')
  else:
    raise TypeError('Input Type Not Supported')
    
#to hide secret msg into image
def hideDataDCT(image, secret_message, output_filename):
    # Convert the image to YCbCr color space
    image_ycbcr = cv2.cvtColor(image, cv2.COLOR_BGR2YCrCb)
    Y = image_ycbcr[:,:,0]

    # Apply 2D DCT to the luminance component (Y channel)
    dct_Y = dct(dct(Y, axis=0, norm='ortho'), axis=1, norm='ortho')

    # Embed the secret message into DCT coefficients
    message_index = 0
    for i in range(8):
        for j in range(8):
            if message_index < len(secret_message):
                dct_Y[i, j] += int(secret_message[message_index]) - 48  # Assuming secret_message is a binary string
                message_index += 1

    # Apply inverse 2D DCT to get the watermarked image
    watermarked_Y = idct(idct(dct_Y, axis=0, norm='ortho'), axis=1, norm='ortho')

    # Replace the luminance component in the YCbCr image
    watermarked_image_ycbcr = image_ycbcr.copy()
    watermarked_image_ycbcr[:,:,0] = watermarked_Y

    # Convert back to BGR color space
    watermarked_image = cv2.cvtColor(watermarked_image_ycbcr, cv2.COLOR_YCrCb2BGR)

    # Save the watermarked image as JPG
    cv2.imwrite(output_filename, watermarked_image)

    return watermarked_image

def showDataDCT(image):
    # Convert the image to YCbCr color space
    image_ycbcr = cv2.cvtColor(image, cv2.COLOR_BGR2YCrCb)
    Y = image_ycbcr[:,:,0]

    # Apply 2D DCT to the luminance component (Y channel)
    dct_Y = dct(dct(Y, axis=0, norm='ortho'), axis=1, norm='ortho')

    # Extract the hidden message from DCT coefficients
    extracted_message = ""
    for i in range(8):
        for j in range(8):
            extracted_message += str(int(dct_Y[i, j] % 2))

    return extracted_message

#encode data into image
def encode_text_dct():
    watermark_image_name = input('Enter watermark image name(with extension): ')
    image_name = input('Enter the image name(with extension): ')
    secret_message = input("Enter Secret Message to be embedded : ")
    output_filename = input("Enter the name of the watermarked image (with extension and as JPG): ")

    image = cv2.imread(image_name)
    watermarked_image = hideDataDCT(image, secret_message, output_filename)

    cv2.imshow('Original Image', image)
    cv2.imshow('Watermarked Image', watermarked_image)
    cv2.waitKey(0)
    cv2.destroyAllWindows()

def decode_text_dct():
    image_name = input('Enter the name of the watermarked image that you want to decode (with extension): ')
    watermarked_image = cv2.imread(image_name)
    extracted_message = showDataDCT(watermarked_image)

    if extracted_message is not None:
        print("Decoded message is:", extracted_message)
        return extracted_message
    else:
        print("Decoding failed. No message extracted.")
        return ""  # Return an empty string or handle this case accordingly

#Peak to noise ratio - compares quality of image
def psnr(orig, watermarked):
    mse = np.mean((orig - watermarked) ** 2)
    if(mse == 0):
        return 100
    
    PIXEL_MAX = 255.0
    return 20 * np.log10(PIXEL_MAX / np.sqrt(mse))

#Normalized Cross-Correlation - compares the similarity between images
def ncc(orig, stego):
    mean_orig = np.mean(orig)
    mean_stego = np.mean(stego)
    norm_orig = orig - mean_orig
    norm_stego = stego - mean_stego
    ncc = (np.mean(norm_orig * norm_stego)) / (np.std(norm_orig) * np.std(norm_stego))
    return ncc

def LSB():
    image_name = ''
    watermarked_image = 0
    a = input("Digital Image Watermarking \n 1. Embed the data \n 2. Extract the data \n Your input is: ")
    userinput = int(a)
    if (userinput == 1):
      print("\nEmbedding....")
      encode_text_dct()

    elif (userinput == 2):
      print("\nExtracting....")
      print("Decoded message is " + decode_text_dct())
      psnr_value = psnr(image_name, watermarked_image)
      print(f"PSNR between original and LSB encoded image: {psnr_value:.2f} dB")

      ncc_value = ncc(image_name, watermarked_image)
      print(f"NCC value is: {ncc_value:.4f}")
    else:
        raise Exception("Enter correct input")

# Check if the key files already exist
if not os.path.exists(PRIVATE_KEY_FILE_PATH) or not os.path.exists(PUBLIC_KEY_FILE_PATH):
    # Generate and save RSA key pair if not already saved
    print("KEYS DOES NOT EXIST")
    private_key, public_key = generate_and_save_rsa_key_pair()
else:
    # Load RSA key pair from disk
    print("KEYS ALREADY EXIST")
    private_key, public_key = load_rsa_key_pair_from_disk()

# Encrypt the message with the recipient's public key (recipient's public key should be known to the sender)
recipient_public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

LSB() #embed image