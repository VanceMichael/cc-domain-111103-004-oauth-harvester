import json
import unittest
from pathlib import Path
from app.oauth import load_grants
class DomainTests(unittest.TestCase):
    def test_organizations(self): self.assertEqual(set(load_grants()),{"cooperative-a","cooperative-b"})
    def test_generation(self): self.assertEqual(load_grants()["cooperative-a"].generation,4)
    def test_duplicate(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path
        with TemporaryDirectory() as d:
            p=Path(d)/"g.json";p.write_text('[{"organization":"x","generation":1,"expires_at":0},{"organization":"x","generation":2,"expires_at":0}]')
            with self.assertRaises(ValueError): load_grants(p)

class FixtureTests(unittest.TestCase):
    def test_fixture_directory(self): self.assertTrue(Path("fixtures").is_dir())
