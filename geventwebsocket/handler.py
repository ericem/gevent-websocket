import base64
import re
import struct
from hashlib import md5, sha1
from socket import error as socket_error
import urlparse

from gevent.pywsgi import WSGIHandler

from .hybi import WebSocketHybi
from .hixie import WebSocketHixie


class WebSocketHandler(WSGIHandler):
    """
    Automatically upgrades the connection to websockets.

    To prevent the WebSocketHandler to call the underlying WSGI application,
    but only setup the WebSocket negotiations, do:

      mywebsockethandler.prevent_wsgi_call = True

    before calling handle_one_response().  This is useful if you want to do
    more things before calling the app, and want to off-load the WebSocket
    negotiations to this library.  Socket.IO needs this for example, to
    send the 'ack' before yielding the control to your WSGI app.
    """

    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    SUPPORTED_VERSIONS = ('13', '8', '7')

    @property
    def ws_url(self):
        return reconstruct_url(self.environ)

    def run_application(self):
        environ = self.environ
        upgrade = environ.get('HTTP_UPGRADE', '').lower()

        if upgrade == 'websocket':
            connection = environ.get('HTTP_CONNECTION', '').lower()

            if connection == 'upgrade':
                if self.maybe_handle_websocket():
                    # the request was handled, probably with an error status

                    self.result = self.result or []
                    self.process_result()

                    return

        # from this point a valid websocket object is available in
        # self.environ['websocket']
        self.close_connection = True

        if hasattr(self, 'prevent_wsgi_call') and self.prevent_wsgi_call:
            return

        # since we're now a websocket connection, we don't care what the
        # application actually responds with for the http response
        self.application(self.environ, self._fake_start_response)

    def _fake_start_response(self, *args, **kwargs):
        pass

    def maybe_handle_websocket(self):
        environ = self.environ

        if environ.get('HTTP_SEC_WEBSOCKET_VERSION'):
            return self._handle_hybi()
        elif environ.get('HTTP_ORIGIN'):
            return self._handle_hixie()

        return False

    def _handle_hybi(self):
        environ = self.environ
        version = environ.get("HTTP_SEC_WEBSOCKET_VERSION")

        environ['wsgi.websocket_version'] = 'hybi-%s' % version

        if version not in self.SUPPORTED_VERSIONS:
            self.log_error('400: Unsupported Version: %r', version)
            self.respond(
                '400 Unsupported Version',
                [('Sec-WebSocket-Version', '13, 8, 7')]
            )
            return

        protocol, version = self.request_version.split("/")
        key = environ.get("HTTP_SEC_WEBSOCKET_KEY")

        # check client handshake for validity
        if not environ.get("REQUEST_METHOD") == "GET":
            # 5.2.1 (1)
            self.respond('400 Bad Request')
            return
        elif not protocol == "HTTP":
            # 5.2.1 (1)
            self.respond('400 Bad Request')
            return
        elif float(version) < 1.1:
            # 5.2.1 (1)
            self.respond('400 Bad Request')
            return
        # XXX: nobody seems to set SERVER_NAME correctly. check the spec
        #elif not environ.get("HTTP_HOST") == environ.get("SERVER_NAME"):
            # 5.2.1 (2)
            #self.respond('400 Bad Request')
            #return
        elif not key:
            # 5.2.1 (3)
            self.log_error('400: HTTP_SEC_WEBSOCKET_KEY is missing from request')
            self.respond('400 Bad Request')
            return
        elif len(base64.b64decode(key)) != 16:
            # 5.2.1 (3)
            self.log_error('400: Invalid key: %r', key)
            self.respond('400 Bad Request')
            return

        self.websocket = WebSocketHybi(self.socket, environ)
        environ['wsgi.websocket'] = self.websocket

        headers = [
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Accept", base64.b64encode(sha1(key + self.GUID).digest())),
        ]
        self._send_reply("101 Switching Protocols", headers)
        return True

    def _handle_hixie(self):
        environ = self.environ

        self.websocket = WebSocketHixie(self.socket, environ)
        environ['wsgi.websocket'] = self.websocket

        key1 = self.environ.get('HTTP_SEC_WEBSOCKET_KEY1')
        key2 = self.environ.get('HTTP_SEC_WEBSOCKET_KEY2')

        if key1 is not None:
            environ['wsgi.websocket_version'] = 'hixie-76'
            if not key1:
                self.log_error("400: SEC-WEBSOCKET-KEY1 header is empty")
                self.respond('400 Bad Request')
                return
            if not key2:
                self.log_error("400: SEC-WEBSOCKET-KEY2 header is missing or empty")
                self.respond('400 Bad Request')
                return

            part1 = self._get_key_value(key1)
            part2 = self._get_key_value(key2)
            if part1 is None or part2 is None:
                self.respond('400 Bad Request')
                return

            headers = [
                ("Upgrade", "WebSocket"),
                ("Connection", "Upgrade"),
                ("Sec-WebSocket-Location", reconstruct_url(environ)),
            ]
            if self.websocket.protocol is not None:
                headers.append(("Sec-WebSocket-Protocol", self.websocket.protocol))
            if self.websocket.origin:
                headers.append(("Sec-WebSocket-Origin", self.websocket.origin))

            self._send_reply("101 WebSocket Protocol Handshake", headers)

            # This request should have 8 bytes of data in the body
            key3 = self.rfile.read(8)

            challenge = md5(struct.pack("!II", part1, part2) + key3).digest()

            self.socket.sendall(challenge)
            return True
        else:
            environ['wsgi.websocket_version'] = 'hixie-75'
            headers = [
                ("Upgrade", "WebSocket"),
                ("Connection", "Upgrade"),
                ("WebSocket-Location", reconstruct_url(environ)),
            ]

            if self.websocket.protocol is not None:
                headers.append(("WebSocket-Protocol", self.websocket.protocol))
            if self.websocket.origin:
                headers.append(("WebSocket-Origin", self.websocket.origin))

            self._send_reply("101 Web Socket Protocol Handshake", headers)

    def _send_reply(self, status, headers):
        self.status = status

        towrite = []
        towrite.append('%s %s\r\n' % (self.request_version, self.status))

        for header in headers:
            towrite.append("%s: %s\r\n" % header)

        towrite.append("\r\n")
        msg = ''.join(towrite)
        self.socket.sendall(msg)
        self.headers_sent = True

    def respond(self, status, headers=None):
        self.close_connection = True
        self._send_reply(status, headers or [])

        if self.socket is not None:
            try:
                self.socket._sock.close()
                self.socket.close()
            except socket_error:
                pass

    def _get_key_value(self, key_value):
        key_number = int(re.sub("\\D", "", key_value))
        spaces = re.subn(" ", "", key_value)[1]

        if key_number % spaces != 0:
            self.log_error("key_number %d is not an intergral multiple of spaces %d", key_number, spaces)
        else:
            return key_number / spaces


def reconstruct_url(environ):
    """
    Build a WebSocket url based on the supplied environ dict.

    Will return a url of the form:

        ws://host:port/path?query
    """
    secure = environ['wsgi.url_scheme'].lower() == 'https'

    if secure:
        scheme = 'wss://'
    else:
        scheme = 'ws://'

    host = environ.get('HTTP_HOST', None)

    if not host:
        host = environ['SERVER_NAME']

    port = None
    server_port = environ['SERVER_PORT']

    if secure:
        if server_port != '443':
            port = server_port
    else:
        if server_port != '80':
            port = server_port

    netloc = host

    if port:
        netloc = host + ':' + port

    path = environ.get('SCRIPT_NAME', '') + environ.get('PATH_INFO', '')

    query = environ['QUERY_STRING']

    return urlparse.urlunparse((
        scheme,
        netloc,
        path,
        '',  # params
        query,
        '',  # fragment
    ))
