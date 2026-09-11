"""Navigation menu entries for the Device Auto-Discovery plugin."""

from nautobot.core.apps import NavMenuAddButton, NavMenuGroup, NavMenuItem, NavMenuTab
from nautobot.core.ui.choices import NavigationIconChoices, NavigationWeightChoices

APP = "nautobot_plugin_device_auto_discovery"

menu_items = (
    NavMenuTab(
        name="Devices",
        weight=NavigationWeightChoices.DEVICES,
        icon=NavigationIconChoices.DEVICES,
        groups=(
            NavMenuGroup(
                weight=650,
                name="Discovery",
                items=(
                    NavMenuItem(
                        link=f"plugins:{APP}:discovereddevice_list",
                        name="Discovered Devices",
                        permissions=[f"{APP}.view_discovereddevice"],
                    ),
                    NavMenuItem(
                        link=f"plugins:{APP}:discoveryprofile_list",
                        name="Discovery Profiles",
                        permissions=[f"{APP}.view_discoveryprofile"],
                        buttons=(
                            NavMenuAddButton(
                                link=f"plugins:{APP}:discoveryprofile_add",
                                permissions=[f"{APP}.add_discoveryprofile"],
                            ),
                        ),
                    ),
                    NavMenuItem(
                        link=f"plugins:{APP}:discoveryscan_list",
                        name="Discovery Scans",
                        permissions=[f"{APP}.view_discoveryscan"],
                    ),
                    NavMenuItem(
                        link=f"plugins:{APP}:discoveryresult_list",
                        name="Discovery Results",
                        permissions=[f"{APP}.view_discoveryresult"],
                    ),
                ),
            ),
        ),
    ),
)
