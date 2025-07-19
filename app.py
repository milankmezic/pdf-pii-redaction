import streamlit as st
import pdfplumber
import fitz  # PyMuPDF
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from custom_recognizers import get_custom_recognizers
import io
import pytesseract
from PIL import Image
import requests
import tempfile
import os
import pathlib
from pathlib import Path
import pandas as pd
import datetime

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

def get_file_browser_data(directory_path):
    """
    Get list of directories and PDF files in the specified directory
    """
    items = []
    
    try:
        path = Path(directory_path)
        if not path.exists():
            return items
            
        # Add parent directory option if not at root
        if path.parent != path:
            items.append({
                'name': '📁 .. (Parent Directory)',
                'path': str(path.parent),
                'type': 'parent',
                'size': '',
                'modified': ''
            })
        
        # Get all items in directory
        for item in sorted(path.iterdir()):
            if item.is_dir():
                items.append({
                    'name': f'📁 {item.name}',
                    'path': str(item),
                    'type': 'directory',
                    'size': '',
                    'modified': ''
                })
            elif item.suffix.lower() == '.pdf':
                try:
                    stat = item.stat()
                    size = stat.st_size
                    
                    # Format size
                    if size < 1024:
                        size_str = f"{size} B"
                    elif size < 1024 * 1024:
                        size_str = f"{size / 1024:.1f} KB"
                    else:
                        size_str = f"{size / (1024 * 1024):.1f} MB"
                    
                    # Format modified date
                    modified_time = datetime.datetime.fromtimestamp(stat.st_mtime)
                    modified_str = modified_time.strftime("%Y-%m-%d %H:%M")
                    
                    items.append({
                        'name': f'📄 {item.name}',
                        'path': str(item),
                        'type': 'pdf',
                        'size': size_str,
                        'modified': modified_str,
                        'size_bytes': size,
                        'modified_timestamp': stat.st_mtime
                    })
                except:
                    pass  # Skip files we can't access
    except PermissionError:
        st.error("Permission denied accessing this directory")
    except Exception as e:
        st.error(f"Error accessing directory: {e}")
    
    return items

def create_file_browser(directory_path):
    """
    Create an interactive file browser interface for the main view
    """
    # Initialize session state for file browser
    if 'selected_files' not in st.session_state:
        st.session_state.selected_files = []
    
    st.header(f"📁 Browse Directory: {directory_path}")
    
    # Add parent directory button if not at root
    current_path = Path(directory_path)
    if current_path.parent != current_path:  # Not at root directory
        col1, col2 = st.columns([1, 4])
        with col1:
            if st.button("📁 ⬆️ Go Up", use_container_width=True, help="Go to parent directory"):
                parent_dir = str(current_path.parent)
                st.session_state.current_directory = parent_dir
                # Update URL parameter to reflect current directory
                st.query_params['dir'] = parent_dir
                st.rerun()
        with col2:
            st.write(f"**Parent:** `{current_path.parent}`")
    
    # Get directory contents
    items = get_file_browser_data(directory_path)
    
    # Navigation section
    directories = [item for item in items if item['type'] in ['parent', 'directory']]
    if directories:
        st.subheader("📁 Navigate to Directory")
        
        # Auto-navigate when dropdown selection changes
        def on_directory_change():
            selected_dir = st.session_state.dir_selector
            if selected_dir and selected_dir != st.session_state.current_directory:
                st.session_state.current_directory = selected_dir
                # Update URL parameter to reflect current directory
                st.query_params['dir'] = selected_dir
        
        # Find the index of current directory in the options (default to 0 if not found)
        current_index = 0
        directory_paths = [item['path'] for item in directories]
        try:
            current_index = directory_paths.index(st.session_state.current_directory)
        except ValueError:
            # Current directory not in list, keep default 0
            pass
        
        selected_dir = st.selectbox(
            "Select Directory (auto-navigates on change)",
            options=directory_paths,
            format_func=lambda x: next(item['name'] for item in directories if item['path'] == x),
            key="dir_selector",
            on_change=on_directory_change,
            index=current_index
        )
    
    # PDF files section
    pdf_files = [item for item in items if item['type'] == 'pdf']
    if pdf_files:
        st.subheader("📄 Select PDF Files for Redaction")
        
        # Create DataFrame for the file table
        df_data = []
        for item in pdf_files:
            df_data.append({
                'Select': item['path'] in st.session_state.selected_files,
                'File Name': item['name'].replace('📄 ', ''),
                'Size': item['size'],
                'Modified': item['modified'],
                'Path': item['path']  # Hidden column for tracking
            })
        
        if df_data:
            # Create editable dataframe
            df = pd.DataFrame(df_data)
            edited_df = st.data_editor(
                df.drop('Path', axis=1),  # Don't show path column
                column_config={
                    "Select": st.column_config.CheckboxColumn(
                        "Select",
                        help="Select files to process",
                        default=False,
                    ),
                    "File Name": st.column_config.TextColumn(
                        "File Name",
                        help="PDF file name",
                        disabled=True,
                        width="large"
                    ),
                    "Size": st.column_config.TextColumn(
                        "Size",
                        help="File size",
                        disabled=True,
                        width="small"
                    ),
                    "Modified": st.column_config.TextColumn(
                        "Last Modified",
                        help="Last modification date",
                        disabled=True,
                        width="medium"
                    ),
                },
                disabled=["File Name", "Size", "Modified"],
                hide_index=True,
                use_container_width=True,
                key="file_selector"
            )
            
            # Update selected files based on checkbox changes
            selected_files = []
            for i, row in edited_df.iterrows():
                if row['Select']:
                    # Find the corresponding file path
                    file_name = row['File Name']
                    for item in pdf_files:
                        if item['name'].replace('📄 ', '') == file_name:
                            selected_files.append(item['path'])
                            break
            
            st.session_state.selected_files = selected_files
            
            # Control buttons
            col1, col2, col3 = st.columns(3)
            with col1:
                if st.button("☑️ Select All", use_container_width=True):
                    st.session_state.selected_files = [item['path'] for item in pdf_files]
                    st.rerun()
            
            with col2:
                if st.button("❌ Clear All", use_container_width=True):
                    st.session_state.selected_files = []
                    st.rerun()
            
            with col3:
                if st.session_state.selected_files and st.button("🔒 Redact Selected Files", use_container_width=True, type="primary"):
                    return True  # Signal to process files
            
            # Show selection count
            if selected_files:
                st.success(f"Selected {len(selected_files)} file(s)")
    else:
        st.info("No PDF files found in this directory")
    
    return False  # No processing requested

def download_pdf_from_url(url):
    """
    Download a PDF from a URL and return it as a file-like object
    """
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        # Create a file-like object from the response content
        pdf_content = io.BytesIO(response.content)
        
        # Create a mock uploaded file object
        class MockUploadedFile:
            def __init__(self, content, name):
                self.content = content
                self.name = name
                self.type = "application/pdf"
                self.size = len(content.getvalue())
            
            def read(self, size=-1):
                return self.content.read(size)
            
            def seek(self, position, whence=0):
                return self.content.seek(position, whence)
            
            def tell(self):
                return self.content.tell()
            
            def getvalue(self):
                return self.content.getvalue()
        
        return MockUploadedFile(pdf_content, url.split('/')[-1])
    
    except Exception as e:
        st.error(f"Error downloading PDF: {e}")
        return None

def main():
    # Initialize session state variables first
    if 'disclaimer_accepted' not in st.session_state:
        st.session_state.disclaimer_accepted = False
    
    # Handle URL parameters for directory navigation
    query_params = st.query_params
    if 'dir' in query_params and query_params['dir']:
        # If there's a directory in the URL, use it
        url_directory = query_params['dir']
        if Path(url_directory).exists() and Path(url_directory).is_dir():
            st.session_state.current_directory = url_directory
        else:
            # If the URL directory doesn't exist, fall back to home and clear the param
            st.session_state.current_directory = str(Path.home())
            st.query_params.clear()
            st.query_params['dir'] = st.session_state.current_directory
    elif 'current_directory' not in st.session_state:
        # First time visit - set to home directory
        st.session_state.current_directory = str(Path.home())
        # Set URL parameter to reflect current directory
        st.query_params['dir'] = st.session_state.current_directory
    else:
        # Ensure URL parameter matches current directory
        if 'dir' not in query_params or query_params['dir'] != st.session_state.current_directory:
            st.query_params['dir'] = st.session_state.current_directory
    
    if 'process_mode' not in st.session_state:
        st.session_state.process_mode = None
    
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
        
        # Show general information and disclaimer together
        st.markdown("""
        ### 🔒 PDF PII Redactor - Proof of Concept
        
        **🔒 Secure Document Processing (Proof of Concept)**
        
        This tool demonstrates how AI can help detect and redact Personally Identifiable Information (PII) from PDF documents. It is designed for testing, demonstration, and educational purposes only.
        
        **How to use:**
        - 📁 **Browse Directory**: Enter a local directory path in the sidebar to browse and select multiple PDF files
        - 🌐 **Process URL**: Enter a PDF URL to download and process a single file  
        - 📤 **Upload File**: Upload a single PDF file directly
        
        **Potential use cases:** Exploring privacy workflows for legal, medical, financial, research, and other sensitive documents.
        """)
        
        st.markdown("""
        ### 🔒 Privacy & Security
        - All processing happens locally or in secure cloud environments
        - No data is stored or transmitted to third parties
        - Your documents remain private and secure
        """)
        
        st.markdown("""
        ### 📚 More Information
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
        
        st.warning("""
        **⚠️ IMPORTANT DISCLAIMER**
        
        This is a **PROOF OF CONCEPT** service and is **NOT INTENDED FOR PRODUCTION USE**.
        
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
        
        # URL/Path input section
        st.subheader("🌐 Browse Directory or URL")
        with st.form("url_form"):
            current_path = st.text_input(
                "Directory Path or URL",
                value=st.session_state.current_directory,
                placeholder="Enter local directory path or PDF URL...",
                help="Enter a local directory path to browse files, or paste a PDF URL to download and process"
            )
            
            go_clicked = st.form_submit_button("🔍 Go", use_container_width=True)
        
        # Handle form submission
        if go_clicked and current_path:
            # Check if it's a URL
            if current_path.startswith(('http://', 'https://')):
                st.session_state.process_mode = 'url'
                st.session_state.pdf_url = current_path
                st.rerun()
            else:
                # Handle directory navigation
                if Path(current_path).exists() and Path(current_path).is_dir():
                    st.session_state.current_directory = current_path
                    st.session_state.process_mode = 'browse'
                    # Update URL parameter to reflect current directory
                    st.query_params['dir'] = current_path
                    st.rerun()
                else:
                    st.error("Directory does not exist or is not accessible")
        
        st.divider()
        
        # Hide upload text after first redaction
        if 'has_processed' not in st.session_state:
            st.session_state.has_processed = False
            
        upload_help = None if st.session_state.has_processed else "Upload a PDF file to automatically detect and redact sensitive information"
        
        uploaded_file = st.file_uploader(
            "📤 Or Upload Single PDF",
            type=['pdf'],
            help=upload_help
        )
        
        if uploaded_file is not None:
            # Track uploaded file in session state
            st.session_state.uploaded_file = uploaded_file.name
            st.session_state.process_mode = 'upload'
    
    # Main content area
    # Handle URL processing
    if st.session_state.get('process_mode') == 'url' and 'pdf_url' in st.session_state:
        pdf_url = st.session_state.pdf_url
        
        st.header("🌐 Processing PDF from URL")
        st.write(f"**URL:** {pdf_url}")
        
        # Download and process the PDF
        downloaded_file = download_pdf_from_url(pdf_url)
        if downloaded_file:
            # Process the downloaded file immediately
            with st.spinner(f"Processing {downloaded_file.name}..."):
                # Step 1: Extract text from the PDF
                text = extract_text_from_pdf(downloaded_file)
                
                if text:
                    # Step 2: Use AI to find sensitive information
                    pii_results = detect_pii(text)
                    
                    if pii_results:
                        # Process similar to upload mode
                        entity_categories = {}
                        entity_list = []
                        
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
                            
                            display_category = friendly_names.get(category, category)
                            if display_category not in entity_categories:
                                entity_categories[display_category] = []
                            entity_categories[display_category].append(value)
                        
                        # Step 3: Create redacted PDF
                        redacted_pdf_bytes, audit_trail = redact_pdf_with_pii(downloaded_file, entity_list)
                        
                        if redacted_pdf_bytes:
                            # Show results similar to upload processing
                            st.success("✅ PII Detection and Redaction Complete!")
                            
                            # Download button for redacted PDF
                            st.download_button(
                                label="📥 Download Redacted PDF",
                                data=redacted_pdf_bytes,
                                file_name=f"redacted_{downloaded_file.name}",
                                mime="application/pdf"
                            )
                            
                            # Show redaction details
                            if audit_trail:
                                with st.expander("🔍 View Redaction Details"):
                                    st.info("**Audit Trail:**\n" + "\n".join(audit_trail))
                        else:
                            st.error("❌ Failed to redact PDF")
                    else:
                        st.info("✅ No PII detected in this document")
                else:
                    st.error("❌ Could not extract text from the PDF")
        
        # Clear the URL processing flag
        if st.button("🔙 Back to Browse"):
            st.session_state.process_mode = 'browse'
            # Update URL parameter to reflect current directory
            st.query_params['dir'] = st.session_state.current_directory
            st.rerun()
    
    # Handle file browser mode
    elif st.session_state.get('process_mode') == 'browse':
        should_process = create_file_browser(st.session_state.current_directory)
        
        if should_process and st.session_state.selected_files:
            st.header("📁 Processing Selected Files")
            
            for file_path in st.session_state.selected_files:
                try:
                    with open(file_path, 'rb') as f:
                        file_content = f.read()
                    
                    # Create a mock file object
                    class MockFile:
                        def __init__(self, content, name):
                            self.content = io.BytesIO(content)
                            self.name = name
                            self.type = "application/pdf"
                            self.size = len(content)
                        
                        def read(self, size=-1):
                            return self.content.read(size)
                        
                        def seek(self, position, whence=0):
                            return self.content.seek(position, whence)
                        
                        def tell(self):
                            return self.content.tell()
                        
                        def getvalue(self):
                            return self.content.getvalue()
                    
                    file_obj = MockFile(file_content, Path(file_path).name)
                    
                    st.subheader(f"Processing: {file_obj.name}")
                    
                    with st.spinner(f"Processing {file_obj.name}..."):
                        # Step 1: Extract text from the PDF
                        text = extract_text_from_pdf(file_obj)
                        
                        if text:
                            # Step 2: Use AI to find sensitive information
                            pii_results = detect_pii(text)
                            
                            if pii_results:
                                # Process PII results
                                entity_categories = {}
                                entity_list = []
                                
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
                                    
                                    display_category = friendly_names.get(category, category)
                                    if display_category not in entity_categories:
                                        entity_categories[display_category] = []
                                    entity_categories[display_category].append(value)
                                
                                # Step 3: Create redacted PDF
                                redacted_pdf_bytes, audit_trail = redact_pdf_with_pii(file_obj, entity_list)
                                
                                if redacted_pdf_bytes:
                                    st.success("✅ PII Detection and Redaction Complete!")
                                    
                                    # Download button for redacted PDF
                                    st.download_button(
                                        label="📥 Download Redacted PDF",
                                        data=redacted_pdf_bytes,
                                        file_name=f"redacted_{file_obj.name}",
                                        mime="application/pdf",
                                        key=f"download_browser_{file_obj.name}"
                                    )
                                    
                                    # Show redaction details
                                    if audit_trail:
                                        with st.expander(f"🔍 View Redaction Details - {file_obj.name}"):
                                            st.info("**Audit Trail:**\n" + "\n".join(audit_trail))
                                else:
                                    st.error(f"❌ Failed to redact {file_obj.name}")
                            else:
                                st.info(f"✅ No PII detected in {file_obj.name}")
                        else:
                            st.error(f"❌ Could not extract text from {file_obj.name}")
                
                except Exception as e:
                    st.error(f"❌ Error processing {file_path}: {e}")
    
    # Handle single file upload mode
    elif uploaded_file is not None:
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
    
    # Default view - show file browser or information
    else:
        if st.session_state.get('process_mode') is None:
            # Set default mode to browse
            st.session_state.process_mode = 'browse'
            st.rerun()
        else:
            # Default to browse mode if no specific mode is set
            st.session_state.process_mode = 'browse'
            st.rerun()

if __name__ == "__main__":
    main() 



# The future is bright - Golden Gekko