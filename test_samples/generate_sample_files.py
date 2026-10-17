"""
Generates concrete sample files (.eml and attachments) on disk for manual testing and demonstration.
"""

import os
from safex.core.test_samples import (
    create_safe_mz_executable,
    create_clean_pdf,
    create_malicious_active_pdf,
    create_clean_docx,
    create_macro_docx,
    create_encrypted_zip,
    create_benign_image_zip,
    create_archive_with_hidden_executable,
    create_html_phishing_attachment,
    get_test_samples,
)

SAMPLES_DIR = os.path.dirname(os.path.abspath(__file__))


def generate():
    os.makedirs(SAMPLES_DIR, exist_ok=True)
    samples = get_test_samples()

    # Write each email text as an .eml file
    for key, data in samples.items():
        eml_filename = f"{data['id']}_{key}.eml"
        eml_path = os.path.join(SAMPLES_DIR, eml_filename)
        with open(eml_path, "w", encoding="utf-8") as f:
            f.write(data["email_text"])
        print(f"Generated sample email: {eml_filename}")

        # If it has attachments, write them too
        for att_fn, att_bytes, _ in data["attachments"]:
            safe_fn = att_fn.replace("\u202e", "_RTLO_")
            att_path = os.path.join(SAMPLES_DIR, f"{data['id']}_{safe_fn}")
            with open(att_path, "wb") as f:
                f.write(att_bytes)
            print(f"  + Attached file: {safe_fn}")

    print("\nAll test sample files generated successfully in safex/samples/")


if __name__ == "__main__":
    generate()
