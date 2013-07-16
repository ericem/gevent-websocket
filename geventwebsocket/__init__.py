version_info = (0, 3, 6)
__version__ = ".".join(map(str, version_info))

__all__ = ['WebSocketHandler', 'WebSocketError', 'upgrade_websocket', 'register_protocol']

from .handler import WebSocketHandler
from .exceptions import WebSocketError
from .wsgi import upgrade_websocket
from .protocols import register_protocol
