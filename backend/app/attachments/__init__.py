"""Attachment analysis."""

from app.attachments.analyze import analyze_attachment, analyze_attachments
from app.attachments.filetypes import detect_type

__all__ = ["analyze_attachment", "analyze_attachments", "detect_type"]
