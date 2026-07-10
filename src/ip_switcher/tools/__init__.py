from .mtputty import dialog as mtputty_dialog
from .phone_configurator import dialog as phone_configurator_dialog

TOOLS = [
    ("MTPuTTY XML generator...", mtputty_dialog.show),
    ("Phone configurator...", phone_configurator_dialog.show),
]
