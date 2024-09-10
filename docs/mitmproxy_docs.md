# Mitmproxy docs

<https://docs.mitmproxy.org/stable/>


**[API docs](https://docs.mitmproxy.org/stable/api/events.html)**

## [mimtproxy.websocket](https://docs.mitmproxy.org/stable/api/mitmproxy/websocket.html)

### What we use so far

#### WebSocketMessage
- `from_client`: `bool`
    - True if this messages was sent by the client.

- `content`: `bytes`
    - The message content.

- `injected`: `bool`
    - True if the message was injected and did not originate from a client/server, False otherwise

#### WebSocketData

- `messages`: `list[WebSocketData]`
    - All WebSocketMessages transferred over this flow.


## What is nice to look at

- `timestamp`: `float`
    - The timestamp of when this message was received or created.
    - POSSIBLE USE: order messages by timestamp

- `dropped`: `bool`
    - True if the message has not been forwarded by mitmproxy, False otherwise.
    - POSSIBLE USE: track which messages were dropped (if any)

- `def drop(self) -> None`
    - Drop this message, i.e. don't forward it to the other peer.
    - Original use case: drop each websocket message regarding Signal messages
    - POSSIBLE USE: drop messages that are not needed

## [mitmproxy.proxy.context](https://docs.mitmproxy.org/stable/api/mitmproxy/proxy/context.html)

### What is nice to look at

- `ctx`
    _The context object provided to each protocol layer in the proxy core._

## [ mitmproxy.http](https://docs.mitmproxy.org/stable/api/mitmproxy/http.html)

### What we use so far

#### HTTPFlow

- `request`: `Request`
    - The HTTP request.

- `response`: `Response`
    - The HTTP response.

- `websocket`: `WebSocketData`
    - The WebSocket connection.

##### Message 

- `content`: `bytes`
    - The uncompressed HTTP message body as bytes. Accessing this attribute may raise a ValueError when the HTTP content-encoding is invalid. See also: `Message.raw_content`, `Message.text`


#### Request

- `method`: `str`
    - The HTTP method.

- `host/pretty_host`: `str`
    - The request host (formatted differently).

- `path/url/pretty_url`: `str`
    - The request path.

#### Response

- `status_code`: `int`
    - The HTTP status code.

### What is nice to look at

##### Message 
    Base class for Request and Response.

- `stream`: `bool`
        This attribute controls if the message body should be streamed.
        If False, mitmproxy will buffer the entire body before forwarding it to the destination. This makes it possible to perform string replacements on the entire body. If True, the message body will not be buffered on the proxy but immediately forwarded instead. Alternatively, a transformation function can be specified, which will be called for each chunk of data. Please **note that packet boundaries generally should not be relied upon**.
        This attribute must be set in the `requestheaders` or `responseheaders` hook. **Setting it in request or response is already too late**, mitmproxy has buffered the message body already.

- `text`: `str | None`

- `def set_content(self, value: bytes | None) -> None`

- `def get_content(self, strict: bool = True) -> bytes | None`

-  `def set_text(self, text: str | None) -> None`
- 
-  `def get_text(self, strict: bool = True) -> str | None`

-  `def decode(self, strict: bool = True) -> None`

-  `def encode(self, encoding: str) -> None`

-  `def json(self, **kwargs: Any) -> Any`

#### Request

- `query`: `dict[str, str]`
    - The request query string as a mutable mapping view on the request's path. For the most part, this behaves like a dictionary. Modifications to the `MultiDictView` update `Request.path`, and vice versa.

#### Headers

In general, this can be interesting to look at, as it provides a lot of information about the request/response headers.