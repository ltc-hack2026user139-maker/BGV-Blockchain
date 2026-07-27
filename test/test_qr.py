"""Test QR decoding on the extracted QR image with aggressive preprocessing."""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import cv2
import numpy as np
from PIL import Image, ImageFilter, ImageEnhance

img_path = "debug_img_1_13.png"

print("Testing QR decode on:", img_path)
print("=" * 60)

# Load with PIL
pil_img = Image.open(img_path)
print(f"PIL mode: {pil_img.mode}, size: {pil_img.size}")

# Load with OpenCV
cv_img = cv2.imread(img_path)
print(f"OpenCV shape: {cv_img.shape}, dtype: {cv_img.dtype}")

detector = cv2.QRCodeDetector()

def try_detect(name, img):
    data, pts, _ = detector.detectAndDecode(img)
    if data:
        print(f"  [{name}] FOUND! Length={len(data)}, first 100: {repr(data[:100])}")
        return data
    else:
        print(f"  [{name}] Not detected")
        return None

# Test 1: As loaded
print("\n--- Basic attempts ---")
try_detect("original BGR", cv_img)

gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
try_detect("grayscale", gray)

# Test 2: Threshold variations
print("\n--- Threshold attempts ---")
_, thresh = cv2.threshold(gray, 128, 255, cv2.THRESH_BINARY)
try_detect("binary threshold 128", thresh)

_, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
try_detect("Otsu threshold", thresh)

# Test 3: Scale variations
print("\n--- Scale attempts ---")
for scale in [0.5, 0.75, 1.5, 2.0]:
    h, w = gray.shape
    resized = cv2.resize(gray, (int(w*scale), int(h*scale)), interpolation=cv2.INTER_LANCZOS4)
    try_detect(f"scale {scale}x", resized)

# Test 4: Try wechat QR decoder if available
print("\n--- WeChatQR attempt ---")
try:
    wechat = cv2.wechat_qrcode_WeChatQRCode()
    texts, _ = wechat.detectAndDecode(cv_img)
    if texts:
        print(f"  WeChatQR FOUND! texts={texts[:1]}")
    else:
        print("  WeChatQR: not detected")
except Exception as e:
    print(f"  WeChatQR not available: {e}")

# Test 5: Try PIL-based preprocessing + cv2
print("\n--- PIL preprocessing + cv2 ---")
pil_gray = pil_img.convert('L')

# High contrast
for contrast in [2.0, 3.0, 4.0]:
    enhanced = ImageEnhance.Contrast(pil_gray).enhance(contrast)
    cv_enhanced = cv2.cvtColor(np.array(enhanced), cv2.COLOR_GRAY2BGR)
    result = try_detect(f"contrast {contrast}x", cv_enhanced)
    if result:
        break

# Sharpen
sharpened = pil_gray.filter(ImageFilter.SHARPEN)
cv_sharp = cv2.cvtColor(np.array(sharpened), cv2.COLOR_GRAY2BGR)
try_detect("sharpened", cv_sharp)

# Test 6: Check raw bytes of the QR image for embedded data
print("\n--- Raw bytes check ---")
with open(img_path, 'rb') as f:
    raw = f.read()
print(f"File size: {len(raw)} bytes")
print(f"First 16 bytes: {raw[:16].hex()}")

print("\n" + "=" * 60)
print("DONE")
