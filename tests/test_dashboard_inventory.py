from __future__ import annotations

import unittest

from app_utils.software_inventory import InventoryApp
from ui.dashboard import filter_displayable_inventory_rows


class DashboardInventoryTests(unittest.TestCase):
    def test_filter_keeps_locked_entries_without_a_path_visible(self) -> None:
        visible = filter_displayable_inventory_rows(
            [
                InventoryApp(
                    display_name="Locked Legacy App",
                    executable_name="legacy.exe",
                    path="",
                    is_locked=True,
                    sources=("locked_db",),
                ),
                InventoryApp(
                    display_name="Visible App",
                    executable_name="visible.exe",
                    path=r"C:\Apps\visible.exe",
                    is_locked=False,
                    sources=("registry",),
                ),
            ]
        )

        self.assertEqual([app.display_name for app in visible], ["Locked Legacy App", "Visible App"])

    def test_filter_hides_unlocked_entries_without_a_path(self) -> None:
        visible = filter_displayable_inventory_rows(
            [
                InventoryApp(
                    display_name="Missing Path",
                    executable_name="missing.exe",
                    path="",
                    is_locked=False,
                    sources=("registry",),
                )
            ]
        )

        self.assertEqual(visible, [])


if __name__ == "__main__":
    unittest.main()
