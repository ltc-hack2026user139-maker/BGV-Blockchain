"""Quick test to debug Aadhaar PDF processing."""
import os
import sys
import io

# Fix Windows console encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import pikepdf
import fitz  # PyMuPDF

PDF_PATH = r"EAadhaar_0000003383820320250526144720_200620261751.pdf"
PASSWORD = "LILE2001"

print("=" * 60)
print("AADHAAR PDF DEBUG TEST")
print("=" * 60)

# Step 1: Open with pikepdf
print("\n[1] Opening with pikepdf...")
try:
    pdf = pikepdf.open(PDF_PATH, password=PASSWORD)
    print(f"    OK - PDF opened. Pages: {len(pdf.pages)}")
    
    for i, page in enumerate(pdf.pages):
        print(f"\n    Page {i+1}:")
        print(f"      Keys: {list(page.keys())}")
        if '/Resources' in page:
            res = page['/Resources']
            print(f"      Resource keys: {list(res.keys())}")
            if '/XObject' in res:
                xobjects = res['/XObject']
                print(f"      XObjects: {list(xobjects.keys())}")
                for key in xobjects:
                    obj = xobjects[key]
                    print(f"        {key}: Subtype={obj.get('/Subtype')}, "
                          f"Width={obj.get('/Width')}, Height={obj.get('/Height')}, "
                          f"Filter={obj.get('/Filter')}, "
                          f"ColorSpace={obj.get('/ColorSpace')}")
    pdf.close()
except Exception as e:
    print(f"    ERROR: {e}")

# Step 2: Try PyMuPDF (fitz)
print("\n[2] Opening with PyMuPDF (fitz)...")
try:
    # First save decrypted version
    pdf_pike = pikepdf.open(PDF_PATH, password=PASSWORD)
    decrypted_path = "temp_decrypted.pdf"
    pdf_pike.save(decrypted_path)
    pdf_pike.close()
    
    doc = fitz.open(decrypted_path)
    print(f"    OK - PDF opened. Pages: {len(doc)}")
    
    for i, page in enumerate(doc):
        print(f"\n    Page {i+1}: {page.rect}")
        
        # Render to image
        mat = fitz.Matrix(2.0, 2.0)  # 2x zoom
        pix = page.get_pixmap(matrix=mat)
        img_path = f"debug_page_{i+1}.png"
        pix.save(img_path)
        print(f"    OK - Saved as {img_path} ({pix.width}x{pix.height})")
        
        # List images in page
        images = page.get_images(full=True)
        print(f"    Images in page: {len(images)}")
        for j, img_info in enumerate(images):
            xref = img_info[0]
            base_image = doc.extract_image(xref)
            print(f"      Image {j+1}: xref={xref}, "
                  f"ext={base_image.get('ext')}, "
                  f"size={len(base_image.get('image', b''))} bytes, "
                  f"{base_image.get('width')}x{base_image.get('height')}")
            
            # Save extracted image
            ext = base_image.get('ext', 'png')
            with open(f"debug_img_{i+1}_{j+1}.{ext}", 'wb') as f:
                f.write(base_image['image'])
            print(f"      OK - Saved as debug_img_{i+1}_{j+1}.{ext}")
    
    doc.close()
    os.remove(decrypted_path)
    
except Exception as e:
    import traceback
    print(f"    ERROR: {e}")
    traceback.print_exc()

# Step 3: Try QR detection on extracted images
print("\n[3] QR detection on rendered page...")
try:
    import cv2
    import numpy as np
    from PIL import Image
    
    page_img_path = "debug_page_1.png"
    if os.path.exists(page_img_path):
        img = cv2.imread(page_img_path)
        print(f"    Image loaded: {img.shape}")
        
        detector = cv2.QRCodeDetector()
        data, vertices, _ = detector.detectAndDecode(img)
        if data:
            print(f"    OK - QR detected! Data length: {len(data)} bytes")
            print(f"    QR data (first 200 chars): {repr(data[:200])}")
        else:
            print("    QR not detected on full page, trying cropped regions...")
            
            # Try different crops
            h, w = img.shape[:2]
            crops = [
                ("full", img),
                ("right_half", img[:, w//2:]),
                ("left_half", img[:, :w//2]),
                ("bottom_half", img[h//2:, :]),
                ("top_right", img[:h//2, w//2:]),
                ("bottom_right", img[h//2:, w//2:]),
            ]
            
            for name, crop in crops:
                # Try original
                data, vertices, _ = detector.detectAndDecode(crop)
                if data:
                    print(f"    OK - QR found in '{name}'! Data length: {len(data)}")
                    print(f"    First 200 chars: {repr(data[:200])}")
                    break
                
                # Try grayscale
                gray = cv2.cvtColor(crop, cv2.COLOR_BGR2GRAY)
                data, vertices, _ = detector.detectAndDecode(gray)
                if data:
                    print(f"    OK - QR found in '{name}' (gray)! Data length: {len(data)}")
                    break
                    
                # Try scaled up
                scaled = cv2.resize(crop, (crop.shape[1]*2, crop.shape[0]*2))
                data, vertices, _ = detector.detectAndDecode(scaled)
                if data:
                    print(f"    OK - QR found in '{name}' (2x scale)! Data length: {len(data)}")
                    break
            else:
                print("    WARN - No QR code detected in any region")
    else:
        print("    No page image to scan")
        
except Exception as e:
    import traceback
    print(f"    ERROR: {e}")
    traceback.print_exc()

print("\n" + "=" * 60)
print("DEBUG COMPLETE")
print("=" * 60)
