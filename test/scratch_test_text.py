import fitz

pdf_path = r'c:\Users\nihar\Downloads\Lilesh\EAadhaar_0000003383820320250526144720_200620261751.pdf'
decrypted_path = pdf_path + '.dec.pdf'

def test():
    try:
        doc = fitz.open(decrypted_path)
        with open('scratch_pdf_text.txt', 'w', encoding='utf-8') as f:
            for i, page in enumerate(doc):
                text = page.get_text()
                f.write(f"--- PAGE {i} TEXT ---\n")
                f.write(text.strip() + "\n")
                f.write("-" * 30 + "\n")
        print("Text written to scratch_pdf_text.txt")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    test()
