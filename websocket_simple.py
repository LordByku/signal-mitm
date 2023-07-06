"""Process individual messages from a WebSocket connection."""
import logging
import re

from mitmproxy import http


def websocket_message(flow: http.HTTPFlow):
    assert flow.websocket is not None  # make type checker happy
    # get the latest message
    message = flow.websocket.messages[-1]
    text = b""

    # was the message sent from the client or server?
    if not message.from_client:
        logging.info(f"Client sent a message: {message.content!r}")
        text += message.content

    with open("./dump.txt", "wb") as f:
        f.write(text)

    """
    # manipulate the message content
    message.content = re.sub(rb"^Hello", b"HAPPY", message.content)

    if b"FOOBAR" in message.content:
        # kill the message and not send it to the other endpoint
        message.drop()
    """
