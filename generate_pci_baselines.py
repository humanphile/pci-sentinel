import zipfile, json, os
import xml.etree.ElementTree as ET

excel_path = "Compliance Assessments PCI_2025.xlsx"
output_dir = "src-tauri/baselines/pci_dss"
os.makedirs(output_dir, exist_ok=True)

with zipfile.ZipFile(excel_path, "r") as z:
    strings = []
    if "xl/sharedStrings.xml" in z.namelist():
        root = ET.fromstring(z.read("xl/sharedStrings.xml"))
        for si in root.findall("{http://schemas.openxmlformats.org/spreadsheetml/2006/main}si"):
            t = "".join(node.text for node in si.iter() if node.text)
            strings.append(t)
            
    sheet_data = z.read("xl/worksheets/sheet2.xml")
    root = ET.fromstring(sheet_data)
    
    rows = []
    for row in root.iter("{http://schemas.openxmlformats.org/spreadsheetml/2006/main}row"):
        row_data = {}
        for c in row.iter("{http://schemas.openxmlformats.org/spreadsheetml/2006/main}c"):
            r = c.attrib.get("r")
            t = c.attrib.get("t")
            v = c.find("{http://schemas.openxmlformats.org/spreadsheetml/2006/main}v")
            val = v.text if v is not None else ""
            if t == "s" and val.isdigit():
                val = strings[int(val)]
            col_letter = "".join(filter(str.isalpha, r))
            # Keeping only Columns A through F (A: ReqNum, B: ReqName, C: SubNum, D: SubName, E: ControlNum, F: Desc)
            # Column G (Test of Implementation) is completely excluded.
            if col_letter in ['A', 'B', 'C', 'D', 'E', 'F']:
                row_data[col_letter] = val
        rows.append(row_data)

requirements = {}
for r in rows[2:]: # Skip header rows
    req_num_str = r.get("A", "")
    if req_num_str.isdigit():
        req_num = int(req_num_str)
        if req_num not in requirements:
            requirements[req_num] = []
        requirements[req_num].append(r)

req_titles = {
    1: "Install and Maintain Network Security Controls",
    2: "Apply Secure Configurations to All System Components",
    3: "Protect Stored Account Data",
    4: "Protect Cardholder Data with Strong Cryptography During Transmission Over Open, Public Networks",
    5: "Protect All Systems and Networks from Malicious Software",
    6: "Develop and Maintain Secure Systems and Software",
    7: "Restrict Access to System Components and Cardholder Data by Business Need to Know",
    8: "Identify Users and Authenticate Access to System Components",
    9: "Restrict Physical Access to Cardholder Data",
    10: "Log and Monitor All Access to System Components and Cardholder Data",
    11: "Test Security of Systems and Networks Regularly",
    12: "Support Information Security with Organizational Policies and Programs"
}

for req_num, r_list in requirements.items():
    controls = []
    req_name = req_titles.get(req_num, "PCI DSS Requirement")
    for r in r_list:
        if 'B' in r and r['B']:
            req_name = r['B']
        c_id = r.get("E", "")
        if c_id:
            safe_id = c_id.replace(".", "_")
            controls.append({
                "control_id": c_id,
                "title_en": r.get("D", ""),
                "mandate_text": r.get("F", ""),
                "required_artifacts": [safe_id + "_Policy.pdf", safe_id + "_Evidence.xlsx"],
                "sample_evidence": "The assessor verified that the security controls and operational procedures are implemented and tested in accordance with PCI DSS standards."
            })
            
    filename = os.path.join(output_dir, f"req_{req_num}.json")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump({
            "framework": "PCI DSS v4.0.1",
            "requirement_id": req_num,
            "title": f"Requirement {req_num}: {req_name}",
            "controls": controls
        }, f, indent=2, ensure_ascii=False)
    print(f"Generated req_{req_num}.json with {len(controls)} controls (Columns A-F only).")

print("All 12 requirement baseline files created successfully without external dependencies!")
