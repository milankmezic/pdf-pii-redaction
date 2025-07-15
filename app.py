import streamlit as st
import pdfplumber
import fitz  # PyMuPDF
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from custom_recognizers import get_custom_recognizers
import io
import pytesseract
from PIL import Image

# Set up the page configuration for a nice looking interface
st.set_page_config(
    page_title="PDF PII Redactor",
    page_icon="🔒",
    layout="wide"
)

# Initialize the AI engines we'll use for detecting sensitive information
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Register custom recognizers for better PII detection
for recognizer in get_custom_recognizers():
    analyzer.registry.add_recognizer(recognizer)

def extract_text_from_pdf(pdf_file):
    """
    Extract text from PDF files. If the PDF has text, we use that.
    If it's a scanned document, we fall back to OCR to read the text.
    """
    text = ""
    with pdfplumber.open(pdf_file) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"
            else:
                # If no text found, it's probably a scanned document - use OCR
                im = page.to_image(resolution=300).original
                ocr_text = pytesseract.image_to_string(im)
                text += ocr_text + "\n"
    return text

def detect_pii(text):
    """
    Use Microsoft's Presidio AI to find sensitive information in the text.
    This looks for things like names, addresses, phone numbers, etc.
    """
    try:
        results = analyzer.analyze(text=text, language="en")
        return results
    except Exception as e:
        st.error(f"Error detecting PII: {str(e)}")
        return []

def redact_pdf_with_pii(pdf_file, pii_entities):
    """
    Take the PDF and actually redact (black out) the sensitive information
    that we found. This creates a new PDF with the sensitive parts covered up.
    """
    try:
        pdf_file.seek(0)
        pdf_document = fitz.open(stream=pdf_file.read(), filetype="pdf")
        pdf_file.seek(0)
        redacted_pdf = fitz.open()
        audit_trail = []
        
        # Go through each page and look for sensitive information to redact
        for page_num in range(len(pdf_document)):
            page = pdf_document[page_num]
            page_text = page.get_text().lower()
            redactions_on_page = 0
            
            # For each piece of sensitive info we found, redact it on this page
            for entity in pii_entities:
                entity_text = entity['text']
                entity_type = entity['entity_type']
                if not entity_text or not entity_text.strip():
                    continue

                # List of labels to preserve
                labels = ['Address:', 'Email:', 'Phone:', 'Name:', 'SSN:', 'MRN:']
                entity_text_stripped = entity_text.strip()
                for label in labels:
                    if entity_text_stripped.startswith(label):
                        # Only redact the value after the label
                        entity_text = entity_text_stripped[len(label):].strip()
                        break

                if not entity_text:
                    continue

                # Find all instances of this sensitive text on the page
                matches = page.search_for(entity_text)
                for rect in matches:
                    # Create a redaction annotation (black box) over the sensitive text
                    redact_annot = page.add_redact_annot(rect)
                    redact_annot.set_colors(stroke=(0, 0, 0), fill=(0, 0, 0))  # Black box
                    redact_annot.update()
                    redactions_on_page += 1
            
            # Apply all the redactions we just created
            page.apply_redactions()
            if redactions_on_page > 0:
                audit_trail.append(f"Page {page_num+1}: {redactions_on_page} redactions")
        
        # Clean up any metadata that might contain sensitive info
        pdf_document.set_metadata({})
        
        # Create the final redacted PDF
        redacted_pdf.insert_pdf(pdf_document)
        redacted_bytes = redacted_pdf.write(garbage=4, deflate=True)
        redacted_pdf.close()
        pdf_document.close()
        return redacted_bytes, audit_trail
    except Exception as e:
        st.error(f"Error redacting PDF: {str(e)}")
        return None, []

def main():
    # Initialize session state variables first
    if 'disclaimer_accepted' not in st.session_state:
        st.session_state.disclaimer_accepted = False
    
    # Main interface - this is what users see when they visit the app
    # Hide the title when processing is done
    if 'uploaded_file' not in st.session_state or st.session_state.get('uploaded_file') is None:
        if not st.session_state.disclaimer_accepted:
            st.title("🔒 PDF PII Redactor - Proof of Concept")
    
    # Show the disclaimer first - users must accept this before they can use the app
    # Disclaimer - User must approve (only show once)
    
    if not st.session_state.disclaimer_accepted:
        disclaimer_accepted = st.checkbox(
            "I acknowledge and accept the following disclaimer:",
            key="disclaimer_checkbox"
        )
        
        if disclaimer_accepted:
            st.session_state.disclaimer_accepted = True
            st.rerun()
        
        st.warning("""
        **⚠️ IMPORTANT DISCLAIMER**
        
        This is a **PROOF OF CONCEPT** service and is **NOT INTENDED FOR PRODUCTION USE**.
        
        **Proof of Concept**
        
        This service works both in cloud and locally for maximum privacy and security. All processing happens on your local machine or secure cloud environment.
        
        - This service is provided "AS IS" without any warranties
        - No guarantee is provided for complete or accurate PII detection
        - Users are responsible for verifying redaction results
        - The developer assumes no liability for missed redactions or data breaches
        - Do not use for sensitive documents without manual verification
        - This tool is for educational and testing purposes only
        
        By checking the box above, you acknowledge these limitations and agree to use this service at your own risk.
        """)
        st.stop()
    
    # File upload section - moved to sidebar
    with st.sidebar:
        st.header("PDF PII Redactor")
        
        # Hide upload text after first redaction
        if 'has_processed' not in st.session_state:
            st.session_state.has_processed = False
            
        upload_help = None if st.session_state.has_processed else "Upload a PDF file to automatically detect and redact sensitive information"
        
        uploaded_file = st.file_uploader(
            "",
            type=['pdf'],
            help=upload_help
        )
        
        if uploaded_file is not None:
            # Track uploaded file in session state
            st.session_state.uploaded_file = uploaded_file.name
    
    # Main content area
    if uploaded_file is not None:
        # Check if we've already processed this file to avoid duplicates
        if 'last_processed_file' not in st.session_state:
            st.session_state.last_processed_file = None
            
        if st.session_state.last_processed_file != uploaded_file.name:
            st.session_state.last_processed_file = uploaded_file.name
        # Automatically process the PDF when uploaded
        with st.spinner("Processing PDF..."):
            # Step 1: Extract text from the PDF
            text = extract_text_from_pdf(uploaded_file)
            if text:
                
                # Step 2: Use AI to find sensitive information
                pii_results = detect_pii(text)
                if pii_results:
                    
                    # Organize the findings by type (names, addresses, etc.)
                    entity_categories = {}
                    entity_list = []
                    
                    # Friendly names for better display
                    friendly_names = {
                        "US_SSN": "Social Security Number",
                        "MEDICAL_RECORD": "Medical Record #",
                        "DEVICE_ID": "Device ID",
                        "LICENSE_PLATE": "License Plate",
                        "FULL_ADDRESS": "Address",
                        "POSTAL_CODE": "Postal Code"
                    }
                    
                    for entity in pii_results:
                        category = entity.entity_type
                        value = text[entity.start:entity.end]
                        entity_list.append({'text': value, 'entity_type': category})
                        
                        # Use friendly name for display if available
                        display_category = friendly_names.get(category, category)
                        if display_category not in entity_categories:
                            entity_categories[display_category] = []
                        entity_categories[display_category].append(value)
                    
                    # Step 3: Actually redact the PDF
                    redacted_pdf_bytes, audit_trail = redact_pdf_with_pii(uploaded_file, entity_list)
                    
                    if redacted_pdf_bytes:
                        # Mark that user has processed a file
                        st.session_state.has_processed = True
                        
                        # 1. Show preview first
                        try:
                            pdf_document = fitz.open(stream=redacted_pdf_bytes, filetype="pdf")
                            if len(pdf_document) > 0:
                                # Show all pages
                                for page_num in range(len(pdf_document)):
                                    page = pdf_document[page_num]
                                    pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))
                                    img_data = pix.tobytes("png")
                                    st.image(img_data, caption=f"Page {page_num + 1} of redacted PDF")
                            pdf_document.close()
                        except Exception as e:
                            st.warning(f"Could not generate preview: {str(e)}")
                        
                        # 2. Open PDF button next
                        # Create a temporary file to serve the PDF
                        import tempfile
                        import base64
                        
                        # Encode PDF data for browser display
                        pdf_base64 = base64.b64encode(redacted_pdf_bytes).decode()
                        pdf_display = f'data:application/pdf;base64,{pdf_base64}'
                        
                        # Create columns for buttons
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            # Create HTML for opening PDF in new tab
                            pdf_html = f'''
                            <a href="{pdf_display}" target="_blank" style="text-decoration: none;">
                                <button style="
                                    background-color: #3498db;
                                    color: white;
                                    padding: 10px 20px;
                                    border: none;
                                    border-radius: 5px;
                                    cursor: pointer;
                                    font-size: 16px;
                                    font-weight: bold;
                                    width: 100%;
                                ">
                                    📄 Open Redacted PDF
                                </button>
                            </a>
                            '''
                            
                            st.markdown(pdf_html, unsafe_allow_html=True)
                        
                        with col2:
                            # Also provide download option
                            st.download_button(
                                label="💾 Download Redacted PDF",
                                data=redacted_pdf_bytes,
                                file_name=f"redacted_{uploaded_file.name}",
                                mime="application/pdf",
                                type="secondary",
                                key=f"download_{uploaded_file.name}"
                            )
                        
                        # 3. Details about redaction
                        st.subheader("🔍 Redaction Details")
                        
                        # Show what we redacted for transparency
                        if audit_trail:
                            st.info("**Audit Trail:**\n" + "\n".join(audit_trail))
                        
                        # Show PII detection summary
                        if pii_results:
                            st.subheader("📊 Redaction Summary")
                            cols = st.columns(3)
                            for i, (category, entities) in enumerate(entity_categories.items()):
                                with cols[i % 3]:
                                    st.metric(category, len(entities))
                                    st.write("**Examples:**")
                                    for entity in entities[:3]:
                                        st.write(f"• {entity}")
                    else:
                        st.error("❌ Failed to redact PDF")
                else:
                    st.success("✅ No PII detected in the document")
            else:
                st.error("❌ Failed to extract text from PDF")
    else:
        # Show information when no file is uploaded
        st.header("🔒 PDF PII Redactor - Proof of Concept")
        st.markdown("""
        **🔒 Secure Document Processing (Proof of Concept)**
        
        This tool demonstrates how AI can help detect and redact Personally Identifiable Information (PII) from PDF documents. It is designed for testing, demonstration, and educational purposes only.
        
        **Potential use cases:** Exploring privacy workflows for legal, medical, financial, research, and other sensitive documents.
        
        _No guarantees of accuracy or compliance. Users are responsible for verifying all results. Not intended for production use._
        """)
        st.header("🔒 Privacy & Security")
        st.markdown("""
        - All processing happens locally or in secure cloud environments
        - No data is stored or transmitted to third parties
        - Your documents remain private and secure
        """)
        
        st.header("📚 More Information")
        st.markdown("""
        **GitHub Repository:** [pdf-pii-redaction](https://github.com/milankmezic/pdf-pii-redaction)
        
        **Support & Feedback:**
        - 📝 [Report Issues](https://github.com/milankmezic/pdf-pii-redaction/issues)
        - 💡 [Request Features](https://github.com/milankmezic/pdf-pii-redaction/issues/new)
        - 📖 [View Documentation](https://github.com/milankmezic/pdf-pii-redaction#readme)
        - ⭐ [Star Repository](https://github.com/milankmezic/pdf-pii-redaction)
        - 🔄 [Fork Project](https://github.com/milankmezic/pdf-pii-redaction/fork)
        
        **Commercial Use:** Commercial version managed by [NextAutomatica](https://nextautomatica.com)
        
        **Third-Party Libraries:** This project uses open-source libraries including Microsoft Presidio, PyMuPDF, pdfplumber, and others. Please refer to their respective licenses for commercial use.
        """)

if __name__ == "__main__":
    main() 



# The future is bright - Golden Gekko