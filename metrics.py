# Importing the libraries
from PIL import Image
import numpy as np
from skimage.metrics import peak_signal_noise_ratio, mean_squared_error
import os
import cv2
import matplotlib.pyplot as plt

# Function to get the file size as MB or KB
def format_file_size(file_path):
    size_bytes = os.path.getsize(file_path)
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.2f} KB"
    else:
        return f"{size_bytes} bytes"

# Function to resize the encoded image to match the dimensions of the original image
def resize_encoded_image(original_image_path, encoded_image_path):
    original_image = Image.open(original_image_path)
    width, height = original_image.size
    encoded_image = Image.open(encoded_image_path)
    resized_encoded_image = encoded_image.resize((width, height), Image.LANCZOS)
    resized_encoded_image.save(encoded_image_path)

# Paths to images to process them
original_image_path = 'image.png'
encoded_image_path = 'image-encoded.png'
resize_encoded_image(original_image_path, encoded_image_path)
original_image = np.array(Image.open(original_image_path))
encoded_image = np.array(Image.open(encoded_image_path))
text_size_bytes = 17

# Calculate PSNR, MSE, and number of changed pixels
def calculate_psnr_mse(original_image, encoded_image):
    # Ensure that both images have the same dimensions
    if original_image.shape != encoded_image.shape:
        raise ValueError("Both images must have the same dimensions.")
    # Calculate the squared error for each pixel
    squared_error = np.square(original_image - encoded_image)
    # Calculating MSE (mean squared error)
    mse = np.mean(squared_error)
    # Calculate PSNR using the MSE
    if mse == 0:
        psnr = float('inf')  # PSNR is infinite if MSE is zero 
    else:
        max_pixel_value = 255  # Assuming pixel values are in the range [0, 255]
        psnr = 20 * np.log10(max_pixel_value / np.sqrt(mse))
    return psnr, mse

def calculate_psnr_mse_changed_pixels(original_image, encoded_image):
    # Calculate PSNR and MSE
    psnr, mse = calculate_psnr_mse(original_image, encoded_image)
    return psnr, mse

psnr, mse= calculate_psnr_mse_changed_pixels(original_image, encoded_image)

# Get file sizes and format as MB or KB
original_image_size = format_file_size(original_image_path)
encoded_image_size = format_file_size(encoded_image_path)

# Printing the results
print(f"Original Image Size: {original_image_size}")
print(f"Encoded Image Size: {format_file_size(original_image_path)}")
print(f"Text Size: {text_size_bytes} bytes")
print(f"PSNR: {psnr:.8f} dB")
print(f"MSE: {mse:.8f}")


img1 = cv2.imread('image.png')
img2 = cv2.imread('image-encoded.png')

# Split the images into R, G, B channels
b, g, r = cv2.split(img1)
b_encoded, g_encoded, r_encoded = cv2.split(img2)

# Calculate histograms for the original image
hist_r = cv2.calcHist([r], [0], None, [256], [0, 256])
hist_g = cv2.calcHist([g], [0], None, [256], [0, 256])
hist_b = cv2.calcHist([b], [0], None, [256], [0, 256])

# Calculate histograms for the encoded image
hist_r_encoded = cv2.calcHist([r_encoded], [0], None, [256], [0, 256])
hist_g_encoded = cv2.calcHist([g_encoded], [0], None, [256], [0, 256])
hist_b_encoded = cv2.calcHist([b_encoded], [0], None, [256], [0, 256])

# Create a 2x3 grid of subplots
plt.figure(figsize=(8.333,5.63))

# Plot histograms from the original image in the first row
plt.subplot(2, 3, 1)
plt.plot(hist_r, color='red')
plt.title('hist_r (Original)')
plt.xlabel('Pixel Value')
plt.ylabel('Frequency')

plt.subplot(2, 3, 2)
plt.plot(hist_g, color='green')
plt.title('hist_g (Original)')
plt.xlabel('Pixel Value')
plt.ylabel('Frequency')

plt.subplot(2, 3, 3)
plt.plot(hist_b, color='blue')
plt.title('hist_b (Original)')
plt.xlabel('Pixel Value')
plt.ylabel('Frequency')

# Plot histograms from the encoded image in the second row
plt.subplot(2, 3, 4)
plt.plot(hist_r_encoded, color='red')
plt.title('hist_r_encoded (Encoded)')
plt.xlabel('Pixel Value')
plt.ylabel('Frequency')

plt.subplot(2, 3, 5)
plt.plot(hist_g_encoded, color='green')
plt.title('hist_g_encoded (Encoded)')
plt.xlabel('Pixel Value')
plt.ylabel('Frequency')

plt.subplot(2, 3, 6)
plt.plot(hist_b_encoded, color='blue')
plt.title('hist_b_encoded (Encoded)')
plt.xlabel('Pixel Value')
plt.ylabel('Frequency')

plt.tight_layout()

# Display the plot
plt.show()
