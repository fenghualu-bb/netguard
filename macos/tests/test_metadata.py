import importlib.util
import plistlib
from pathlib import Path
import tempfile
import unittest

path = Path(__file__).resolve().parents[1] / "scripts/generate-metadata.py"
spec = importlib.util.spec_from_file_location("metadata", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MetadataTests(unittest.TestCase):
    def test_unsigned_build_is_explicitly_inactive(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            module.generate(root)
            self.assertIn("isSignedBuild = false", (root / "BuildIdentity.swift").read_text())
            self.assertIn("not active", (root / "BUILD-STATUS.txt").read_text())

    def test_provider_classes_and_service_are_separate(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            module.generate(root, "ABCDEFGHIJ")
            socket = plistlib.loads((root / "socket-Info.plist").read_bytes())
            packet = plistlib.loads((root / "packet-Info.plist").read_bytes())
            self.assertNotEqual(socket["CFBundleIdentifier"], packet["CFBundleIdentifier"])
            self.assertIn("com.apple.networkextension.filter-data", socket["NetworkExtension"]["NEProviderClasses"])
            self.assertIn("com.apple.networkextension.filter-packet", packet["NetworkExtension"]["NEProviderClasses"])
            helper = plistlib.loads((root / "Helper-LaunchDaemon.plist").read_bytes())
            self.assertNotIn("ProgramArguments", helper)
            self.assertEqual(helper["BundleProgram"], "Contents/Library/LaunchServices/NetGuardHelper")

    def test_untrusted_build_identifier_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            for team in ("short", 'ABCDEFGHIJ";bad', "../../secret"):
                with self.assertRaises(ValueError):
                    module.generate(Path(d), team)


if __name__ == "__main__":
    unittest.main()
