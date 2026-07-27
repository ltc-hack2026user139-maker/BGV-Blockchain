from pipelines.passport import compare_mrz_viz, extract_viz_from_text

# Mock data
mrz_data = {
    'full_name': 'LILESH YASHWANT MANDHALKAR',
    'gender_full': 'MALE',
    'nationality': 'IND',
    'dob_formatted': '25/04/2001'
}

raw_text = """
REPUBLIC OF INDIA
MANDHALKAR
LILESH YASHWANT
25/04/2001
MALE
"""

viz_data = extract_viz_from_text(raw_text)

def test():
    print("VIZ DATA:", viz_data)
    result = compare_mrz_viz(mrz_data, viz_data)
    for check in result['checks']:
        print(f"{check['name']}: {check['passed']} ({check.get('detail', '')})")

if __name__ == '__main__':
    test()
