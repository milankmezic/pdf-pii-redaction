# 🔒 PDF PII Redactor - Proof of Concept

**Demonstration tool for exploring AI-powered PDF redaction.**

PDF PII Redactor is a proof of concept that uses AI to detect and redact Personally Identifiable Information (PII) from PDF documents. Built with Microsoft Presidio and designed for local processing, it is intended for testing, demonstration, and educational use only.

**Why Try PDF PII Redactor?**
- **AI-Powered Detection**: Uses Microsoft Presidio to identify common PII
- **Local-First Processing**: Your data stays on your machine
- **Redaction Demo**: Shows how black box redactions can be applied
- **Quick Results**: Process documents in seconds
- **Open Source**: Explore, fork, and adapt for your own research

_Disclaimer: This is a proof of concept. No guarantees of accuracy, completeness, or compliance. Not intended for production or critical use. Users are responsible for verifying all results._

## ✨ Features

- **🔍 Intelligent PII Detection**: Automatically identifies names, addresses, phone numbers, emails, and other sensitive data
- **🔒 Secure Processing**: All processing happens locally or in secure cloud environments
- **📄 Professional Redaction**: Clean, professional redaction with clear markers and audit trails
- **⚡ Easy to Use**: Simple web interface - upload PDF, process, download redacted version
- **🛡️ Privacy First**: No data storage or transmission to third parties

## 🎯 What Gets Redacted

- **Personal Information**: Names, addresses, phone numbers, emails
- **Financial Data**: Credit card numbers, bank account details  
- **Medical Information**: Patient IDs, diagnoses, treatment details
- **Government IDs**: Social Security numbers, passport numbers
- **Business Data**: Trade secrets, proprietary information

## Support us - become a sponsor
- https://github.com/sponsors/milankmezic

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Tesseract OCR (for scanned documents)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/milankmezic/pdf-pii-redaction.git
   cd pdf-pii-redaction
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Tesseract OCR** (for scanned PDF support)
   
   **macOS:**
   ```bash
   brew install tesseract
   ```
   
   **Ubuntu/Debian:**
   ```bash
   sudo apt-get install tesseract-ocr
   ```
   
   **Windows:**
   Download from [GitHub](https://github.com/UB-Mannheim/tesseract/wiki)

5. **Run the application**
   ```bash
   streamlit run app.py
   ```

6. **Open your browser**
   Navigate to `http://localhost:8501`

## 📖 Usage

1. **Upload PDF**: Click "Choose a PDF file" and select your document
2. **Accept Disclaimer**: Read and accept the proof of concept disclaimer
3. **Process**: Click "🔍 Detect and Redact PII" to start processing
4. **Review Results**: See detected PII entities and redaction preview
5. **Download**: Click "📥 Download Redacted PDF" to get your secure document

## 🛠️ Technical Details

### Architecture

- **Frontend**: Streamlit web interface
- **Text Extraction**: pdfplumber for accurate text positioning
- **OCR**: pytesseract for scanned document support
- **PII Detection**: Microsoft Presidio AI engine
- **PDF Processing**: PyMuPDF (fitz) for redaction operations

### Security Features

- **Local Processing**: Documents processed in memory, not stored
- **No Data Persistence**: Files deleted immediately after processing
- **Secure Redaction**: Professional-grade PDF redaction with metadata cleanup
- **Audit Trails**: Detailed logs of all redactions for compliance

## 📋 Requirements

```
streamlit>=1.28.0
PyPDF2>=3.0.0
python-dotenv>=1.0.0
requests>=2.31.0
Pillow>=9.5.0
PyMuPDF>=1.23.0
presidio-analyzer>=2.2.32
presidio-anonymizer>=2.2.32
pdfplumber>=0.10.3
pytesseract
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# Optional: Custom Tesseract path (if not in system PATH)
TESSERACT_CMD=/usr/local/bin/tesseract
```

### Customization

- **Detection Sensitivity**: Modify `detect_pii()` function to adjust detection thresholds
- **Redaction Style**: Customize redaction appearance in `redact_pdf_with_pii()`
- **Supported Languages**: Add language support in Presidio configuration

## 🧪 Testing

Run the test suite:

```bash
python test_setup.py
```

## 📊 Performance

- **Processing Speed**: ~2-5 seconds per page (depending on content)
- **File Size**: Supports PDFs up to 50MB
- **Memory Usage**: Minimal - processes files in memory
- **Accuracy**: High detection rate for common PII types

## 🚨 Important Disclaimer

**This is a PROOF OF CONCEPT service and is NOT INTENDED FOR PRODUCTION USE.**

- No warranties provided
- Users responsible for verifying results
- Not suitable for critical applications without manual review
- Educational and testing purposes only

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

See the [LICENSE](LICENSE) file for details.

## 🆘 Support

For questions, issues, or feature requests:

- **Issues**: Use the [GitHub Issues](https://github.com/milankmezic/pdf-pii-redaction/issues) page
- **Documentation**: Check the code comments and this README
- **Security**: Report security issues privately

## 🙏 Acknowledgments

- **Microsoft Presidio**: PII detection engine
- **pdfplumber**: PDF text extraction
- **PyMuPDF**: PDF processing and redaction
- **Streamlit**: Web application framework

## 📅 Version History

### Version 2.1.0 - Enhanced File Browser (Latest)
*December 2024*

**🆕 New Features:**
- **📁 Interactive Directory Browser**: Browse local directories with dropdown navigation
- **📊 Multi-File Selection**: Select multiple PDF files using interactive dataframes
- **🔗 URL Parameter Support**: Bookmarkable URLs that remember current directory (`?dir=/path/to/folder`)
- **⚡ Auto-Navigation**: Automatic directory changes without manual "Go" button clicks
- **🌐 URL Processing**: Direct processing of PDF files from web URLs
- **📋 Batch Processing**: Process multiple selected files in one operation

**🔧 Interface Improvements:**
- File browser shows file size, modification dates, and organized navigation
- Select All / Clear All buttons for quick file selection
- Enhanced sidebar with three processing modes: Browse, URL, Upload
- Streamlined information flow with details moved to disclaimer page
- Real-time URL updates for easy bookmarking and sharing

**🎯 User Experience:**
- One-click directory navigation via dropdown
- Persistent directory state across browser sessions
- Improved visual feedback and progress indicators
- Cleaner main interface focused on functionality

### Version 1.0.0 - Initial Release
*Earlier 2024*

**Core Features:**
- Single PDF file upload and processing
- AI-powered PII detection using Microsoft Presidio
- Local document processing for privacy
- Professional PDF redaction with audit trails
- OCR support for scanned documents
- Streamlit web interface

## 📈 Roadmap

- [ ] Multi-language support
- [ ] Batch processing
- [ ] Custom PII patterns
- [ ] API endpoint
- [ ] Docker containerization
- [ ] Cloud deployment options

---

**Made with ❤️ for privacy and security**

*Transform your document workflow. Protect your privacy. Ensure compliance.* 
