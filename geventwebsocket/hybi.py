import base64
import hashlib
import struct
from socket import error

from . import exceptions as exc
from .websocket import WebSocket, encode_bytes
from .protocols import SUPPORTED_PROTOCOLS


__all__ = ['upgrade_connection']


OPCODE_CONTINUATION = 0x00
OPCODE_TEXT = 0x01
OPCODE_BINARY = 0x02
OPCODE_CLOSE = 0x08
OPCODE_PING = 0x09
OPCODE_PONG = 0x0a

FIN_MASK = 0x80
OPCODE_MASK = 0x0f
MASK_MASK = 0x80
LENGTH_MASK = 0x7f

RSV0_MASK = 0x40
RSV1_MASK = 0x20
RSV2_MASK = 0x10

# bitwise mask that will determine the reserved bits for a frame header
HEADER_FLAG_MASK = RSV0_MASK | RSV1_MASK | RSV2_MASK


GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SUPPORTED_VERSIONS = ('13', '8', '7')


class Header(object):
    __slots__ = (
        'fin',
        'mask',
        'opcode',
        'flags',
        'length'
    )

    def __init__(self):
        self.fin = 0
        self.mask = ''
        self.opcode = 0
        self.flags = 0
        self.length = 0

    def mask_payload(self, payload):
        payload = bytearray(payload)
        mask = bytearray(self.mask)

        for i in xrange(self.length):
            payload[i] ^= mask[i % 4]

        return str(payload)

    # it's the same operation
    unmask_payload = mask_payload

    def __repr__(self):
        return '<Header fin=%r opcode=%r length=%r flags=%r at 0x%x>' % (
            self.fin, self.opcode, self.length, self.flags, id(self),)


class WebSocketHybi(WebSocket):
    __slots__ = ()

    def _decode_bytes(self, bytestring):
        """
        Internal method used to convert the utf-8 encoded bytestring into
        unicode.

        If the conversion fails, the socket will be closed.
        """
        if not bytestring:
            return u''

        try:
            return bytestring.decode('utf-8')
        except UnicodeDecodeError:
            self.close(1007)

            raise

    def handle_close(self, header, payload):
        """
        Called when a close frame has been decoded from the stream.

        :param header: The decoded `Header`.
        :param payload: The bytestring payload associated with the close frame.
        """
        if not payload:
            self.close(1000, None)

            return

        if len(payload) < 2:
            raise exc.ProtocolError('Invalid close frame: %r %r' % (
                header, payload))

        code = struct.unpack('!H', str(payload[:2]))[0]
        payload = payload[2:]

        if payload:
            payload = self._decode_bytes(payload)

        if not is_valid_close_code(code):
            raise exc.ProtocolError('Invalid close code %r' % (code,))

        self.close(code, payload)

    def handle_ping(self, header, payload):
        self.send_frame(payload, OPCODE_PONG)

    def handle_pong(self, header, payload):
        pass

    def read_frame(self):
        """
        Block until a full frame has been read from the socket.

        This is an internal method as calling this will not cleanup correctly
        if an exception is called. Use `receive` instead.

        :return: The header and payload as a tuple.
        """
        header = decode_header(self.stream)

        if header.flags:
            raise exc.ProtocolError

        if not header.length:
            return header, ''

        try:
            payload = self.raw_read(header.length)
        except error:
            payload = ''
        except Exception:
            # TODO log out this exception
            payload = ''

        if len(payload) != header.length:
            raise exc.WebSocketError('Unexpected EOF reading frame payload')

        if header.mask:
            payload = header.unmask_payload(payload)

        return header, payload

    def read_message(self):
        """
        Return the next text or binary message from the socket.

        This is an internal method as calling this will not cleanup correctly
        if an exception is called. Use `receive` instead.
        """
        opcode = None
        message = ''

        while True:
            header, payload = self.read_frame()
            f_opcode = header.opcode

            if f_opcode in (OPCODE_TEXT, OPCODE_BINARY):
                # a new frame
                if opcode:
                    raise exc.ProtocolError('The opcode in non-fin frame is '
                                            'expected to be zero, got %r' % (
                                                f_opcode,))

                opcode = f_opcode

            elif f_opcode == OPCODE_CONTINUATION:
                if not opcode:
                    raise exc.ProtocolError('Unexpected frame with opcode=0')

            elif f_opcode == OPCODE_PING:
                self.handle_ping(header, payload)

                continue
            elif f_opcode == OPCODE_PONG:
                self.handle_pong(header, payload)

                continue
            elif f_opcode == OPCODE_CLOSE:
                self.handle_close(header, payload)

                return

            else:
                raise exc.ProtocolError("Unexpected opcode=%r" % (f_opcode,))

            message += payload

            if header.fin:
                break

        if opcode == OPCODE_TEXT:
            return self._decode_bytes(message)

        return bytearray(message)

    def receive(self):
        """
        Read and return a message from the stream. If `None` is returned, then
        the socket is considered closed/errored.
        """
        if self.closed:
            return

        try:
            return self.read_message()
        except exc.ProtocolError:
            self.close(1002)

            raise
        except error:
            raise exc.WebSocketError('Socket is dead')

    def send_frame(self, message, opcode):
        """
        Send a frame over the websocket with message as its payload
        """
        if self.closed:
            raise exc.WebSocketError('The connection was closed')

        if opcode == OPCODE_TEXT:
            message = encode_bytes(message)
        elif opcode == OPCODE_BINARY:
            message = str(message)

        header = encode_header(True, opcode, '', len(message), 0)

        try:
            self.raw_write(header + message)
        except error:
            raise exc.WebSocketError('Socket is dead')

    def send(self, message, binary=None):
        """
        Send a frame over the websocket with message as its payload
        """
        if binary is None:
            binary = not isinstance(message, (str, unicode))

        opcode = OPCODE_BINARY if binary else OPCODE_TEXT

        self.send_frame(message, opcode)

    def close(self, code=1000, message=''):
        """
        Close the websocket, sending the specified code and message.

        Set `code` to None if you just want to sever the connection.
        """
        if self.closed:
            return

        if not code:
            super(WebSocketHybi, self).close()

            return

        try:
            message = encode_bytes(message)

            self.send_frame(
                struct.pack('!H%ds' % len(message), code, message),
                opcode=OPCODE_CLOSE)
        except exc.WebSocketError:
            # failed to write the closing frame but it's ok because we're
            # closing the socket anyway.
            pass
        finally:
            super(WebSocketHybi, self).close()


def is_valid_close_code(code):
    """
    :returns: Whether the returned close code is a valid hybi return code.
    """
    if code < 1000:
        return False

    if 1004 <= code <= 1006:
        return False

    if 1012 <= code <= 1016:
        return False

    if code == 1100:
        # not sure about this one but the autobahn fuzzer requires it.
        return False

    if 2000 <= code <= 2999:
        return False

    return True


def decode_header(stream):
    """
    Decode a Hybi header.

    :param stream: A file like object that can be 'read' from.
    :returns: A `Header` instance.
    """
    read = stream.read
    data = read(2)

    if len(data) != 2:
        raise exc.WebSocketError('Unexpected EOF while decoding header')

    first_byte, second_byte = struct.unpack('!BB', data)
    header = Header()

    header.fin = first_byte & FIN_MASK == FIN_MASK
    header.opcode = first_byte & OPCODE_MASK
    header.flags = first_byte & HEADER_FLAG_MASK
    header.length = second_byte & LENGTH_MASK
    has_mask = second_byte & MASK_MASK == MASK_MASK

    if header.opcode > 0x07:
        if not header.fin:
            raise exc.ProtocolError(
                'Received fragmented control frame: %r' % (data,))

        # Control frames MUST have a payload length of 125 bytes or less
        if header.length > 125:
            raise exc.FrameTooLargeException(
                'Control frame cannot be larger than 125 bytes: %r' % (data,))

    if header.length == 126:
        # 16 bit length
        data = read(2)

        if len(data) != 2:
            raise exc.WebSocketError('Unexpected EOF while decoding header')

        header.length = struct.unpack('!H', data)[0]
    elif header.length == 127:
        # 64 bit length
        data = read(8)

        if len(data) != 8:
            raise exc.WebSocketError('Unexpected EOF while decoding header')

        header.length = struct.unpack('!Q', data)[0]

    if has_mask:
        mask = read(4)

        if len(mask) != 4:
            raise exc.WebSocketError('Unexpected EOF while decoding header')

        header.mask = mask

    return header


def encode_header(fin, opcode, mask, length, flags):
    """
    Encodes a Hybi header.

    :param fin: Whether this is the final frame for this opcode.
    :param opcode: The opcode of the payload, see `OPCODE_*`
    :param mask: Whether the payload is masked.
    :param length: The length of the frame.
    :param flags: The RSV* flags.
    :return: A bytestring encoded header.
    """
    first_byte = opcode
    second_byte = 0
    extra = ''

    if fin:
        first_byte |= FIN_MASK

    if flags & RSV0_MASK:
        first_byte |= RSV0_MASK

    if flags & RSV1_MASK:
        first_byte |= RSV1_MASK

    if flags & RSV2_MASK:
        first_byte |= RSV2_MASK

    # now deal with length complexities
    if length < 126:
        second_byte += length
    elif length <= 0xffff:
        second_byte += 126
        extra = struct.pack('!H', length)
    elif length <= 0xffffffffffffffff:
        second_byte += 127
        extra = struct.pack('!Q', length)
    else:
        raise exc.FrameTooLargeException

    if mask:
        second_byte |= MASK_MASK

        extra += mask

    return chr(first_byte) + chr(second_byte) + extra


def upgrade_connection(environ, start_response, stream):
    """
    Validate and 'upgrade' the HTTP request to a WebSocket request.

    If an upgrade succeeded then then handler will have `start_response` with a
    status of `101`, the environ will also be updated with `wsgi.websocket` and
    `wsgi.websocket_version` keys.

    :param environ: The WSGI environ dict.
    :param start_response: The callable used to start the response.
    :param stream: File like object that will be read from/written to by the
        underlying WebSocket object, if created.
    :return: The WSGI response iterator is something went awry.
    """
    version = environ.get("HTTP_SEC_WEBSOCKET_VERSION")

    if version not in SUPPORTED_VERSIONS:
        msg = 'Unsupported WebSocket Version: %r' % (version,)

        start_response('400 Bad Request', [
            ('Sec-WebSocket-Version', '13, 8, 7')
        ])

        return [msg]

    key = environ.get("HTTP_SEC_WEBSOCKET_KEY", '').strip()

    if not key:
        # 5.2.1 (3)
        msg = 'Sec-WebSocket-Key header is missing/empty'

        start_response('400 Bad Request', [])

        return [msg]

    try:
        key_len = len(base64.b64decode(key))
    except TypeError:
        msg = 'Invalid key: %r' % (key,)

        start_response('400 Bad Request', [])

        return [msg]

    if key_len != 16:
        # 5.2.1 (3)
        msg = 'Invalid key: %r' % (key,)

        start_response('400 Bad Request', [])

        return [msg]

    protocol = environ.get("HTTP_SEC_WEBSOCKET_PROTOCOL", '')
    requested_protocols = [p.strip() for p in protocol.split(',') if p]
    accepted_protocols = []
    for p in requested_protocols:
        if p in SUPPORTED_PROTOCOLS:
            accepted_protocols.append(p)

    ws = WebSocketHybi(environ, stream)

    environ.update({
        'wsgi.websocket_version': 'hybi-%s' % version,
        'wsgi.websocket_protocol': accepted_protocols,
        'wsgi.websocket': ws
    })

    headers = [
        ("Upgrade", "websocket"),
        ("Connection", "Upgrade"),
        ("Sec-WebSocket-Accept", base64.b64encode(
            hashlib.sha1(key + GUID).digest())),
    ]

    if protocol:
        headers.append(("Sec-WebSocket-Protocol", ",".join(accepted_protocols)))

    start_response("101 Switching Protocols", headers)
    return []
