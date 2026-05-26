
import os
import sys
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

# Add project root directory (the paracci folder itself)
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.shields.macos import MacOSShield

class TestMacOSShieldStress(unittest.TestCase):
    def setUp(self):
        self.shield = MacOSShield()

    def test_os_name(self):
        self.assertEqual(self.shield.get_os_name(), "macOS")

    def test_data_dir_structure(self):
        # Check macOS path structure
        path = self.shield.get_default_data_dir("Paracci")
        # Normalize path separator (Windows \ -> /)
        normalized_path = path.replace('\\', '/')
        self.assertIn("Library/Application Support", normalized_path)
        self.assertTrue(normalized_path.endswith("Paracci"))

    @patch("subprocess.run")
    def test_clear_recent_documents(self, mock_run):
        # Simulate osascript call
        mock_run.return_value = MagicMock(returncode=0)
        result = self.shield.clear_recent_documents()
        self.assertTrue(result)
        mock_run.assert_called_once()
        self.assertIn("osascript", mock_run.call_args[0][0])

    @patch("subprocess.run")
    def test_clipboard_copy(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)

        result = self.shield.copy_to_clipboard("SecretText", clear_delay=0)
        self.assertTrue(result)
        mock_run.assert_called_with(["pbcopy"], input=b"SecretText", check=True)

    def test_secure_delete_mock(self):
        # Create a temporary file and test secure deletion
        test_file = Path("test_wipe.tmp")
        test_file.write_text("sensitivedata")
        
        result = self.shield.secure_delete(str(test_file))
        self.assertTrue(result)
        self.assertFalse(test_file.exists())

if __name__ == "__main__":
    print("--- Starting macOS Adapter Stress Test ---")
    unittest.main()
