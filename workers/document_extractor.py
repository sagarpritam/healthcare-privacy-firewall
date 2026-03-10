import io
from typing import Optional
import logging

import pandas as pd
import docx
import PyPDF2

logger = logging.getLogger(__name__)

class DocumentExtractor:
    """Extracts text from various document formats (Excel, Word, PDF)."""
    
    @staticmethod
    def extract_text(file_bytes: bytes, filename: str) -> Optional[str]:
        """
        Determine file type from extension and extract text.
        Returns the extracted text as a string, or None if unsupported or failed.
        """
        filename = filename.lower()
        
        try:
            if filename.endswith(('.xlsx', '.xls')):
                return DocumentExtractor._extract_from_excel(file_bytes)
            elif filename.endswith('.docx'):
                return DocumentExtractor._extract_from_word(file_bytes)
            elif filename.endswith('.pdf'):
                return DocumentExtractor._extract_from_pdf(file_bytes)
            elif filename.endswith('.csv'):
                return DocumentExtractor._extract_from_csv(file_bytes)
            elif filename.endswith('.txt'):
                return file_bytes.decode('utf-8', errors='replace')
            else:
                logger.warning(f"Unsupported document format: {filename}")
                return None
        except Exception as e:
            logger.error(f"Error extracting text from {filename}: {e}")
            return None
            
    @staticmethod
    def _extract_from_excel(file_bytes: bytes) -> str:
        """Extract text from Excel file by concatenating all cell values."""
        df = pd.read_excel(io.BytesIO(file_bytes), sheet_name=None)
        text_parts = []
        for sheet_name, sheet_df in df.items():
            text_parts.append(f"--- Sheet: {sheet_name} ---")
            # Convert whole dataframe to string
            text_parts.append(sheet_df.to_string(index=False))
        return "\n".join(text_parts)
        
    @staticmethod
    def _extract_from_csv(file_bytes: bytes) -> str:
        """Extract text from CSV file."""
        df = pd.read_csv(io.BytesIO(file_bytes))
        return df.to_string(index=False)
        
    @staticmethod
    def _extract_from_word(file_bytes: bytes) -> str:
        """Extract text from Word document."""
        doc = docx.Document(io.BytesIO(file_bytes))
        text_parts = [paragraph.text for paragraph in doc.paragraphs]
        return "\n".join(text_parts)
        
    @staticmethod
    def _extract_from_pdf(file_bytes: bytes) -> str:
        """Extract text from PDF document."""
        reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))
        text_parts = []
        for i, page in enumerate(reader.pages):
            text_parts.append(f"--- Page {i+1} ---")
            text = page.extract_text()
            if text:
                text_parts.append(text)
        return "\n".join(text_parts)
