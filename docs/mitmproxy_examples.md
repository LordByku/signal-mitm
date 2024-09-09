# mitmproxy (nice to look at) examples

## [Contentview-custom-grpc](https://docs.mitmproxy.org/stable/addons-examples/#contentview-custom-grpc)

```python
Add a custom version of the gRPC/protobuf content view, which parses protobuf messages based on a user defined rule set.
```


## [commands-flows](https://docs.mitmproxy.org/stable/addons-examples/#commands-flows)
```python
"""Handle flows as command arguments."""

import logging
from collections.abc import Sequence

from mitmproxy import command
from mitmproxy import flow
from mitmproxy import http
from mitmproxy.log import ALERT


class MyAddon:
    @command.command("myaddon.addheader")
    def addheader(self, flows: Sequence[flow.Flow]) -> None:
        for f in flows:
            if isinstance(f, http.HTTPFlow):
                f.request.headers["myheader"] = "value"
        logging.log(ALERT, "done")


addons = [MyAddon()]
```


## [websocket_inject-message](https://docs.mitmproxy.org/stable/addons-examples/#websocket-inject-message)

```python
"""
Inject a WebSocket message into a running connection.

This example shows how to inject a WebSocket message into a running connection.
"""

import asyncio

from mitmproxy import ctx
from mitmproxy import http

# Simple example: Inject a message as a response to an event


def websocket_message(flow: http.HTTPFlow):
    assert flow.websocket is not None  # make type checker happy
    last_message = flow.websocket.messages[-1]
    if last_message.is_text and "secret" in last_message.text:
        last_message.drop()
        ctx.master.commands.call(
            "inject.websocket", flow, last_message.from_client, b"ssssssh"
        )


# Complex example: Schedule a periodic timer


async def inject_async(flow: http.HTTPFlow):
    msg = "hello from mitmproxy! "
    assert flow.websocket is not None  # make type checker happy
    while flow.websocket.timestamp_end is None:
        ctx.master.commands.call("inject.websocket", flow, True, msg.encode())
        await asyncio.sleep(1)
        msg = msg[1:] + msg[:1]


# Python 3.11: replace with TaskGroup
tasks = set()


def websocket_start(flow: http.HTTPFlow):
    # we need to hold a reference to the task, otherwise it will be garbage collected.
    t = asyncio.create_task(inject_async(flow))
    tasks.add(t)
    t.add_done_callback(tasks.remove)
```


## [shutdown](https://docs.mitmproxy.org/stable/addons-examples/#shutdown)
```python
ctx.master.shutdown()
```


## [commands-simple.py](https://docs.mitmproxy.org/stable/addons-examples/#commands-simple)
```python
"""Add a custom command to mitmproxy's command prompt."""

import logging

from mitmproxy import command


class MyAddon:
    def __init__(self):
        self.num = 0

    @command.command("myaddon.inc")
    def inc(self) -> None:
        self.num += 1
        logging.info(f"num = {self.num}")


addons = [MyAddon()]
```


## [websocket-simple](https://docs.mitmproxy.org/stable/addons-examples/#websocket-simple)

```python
"""Process individual messages from a WebSocket connection."""

import logging
import re

from mitmproxy import http


def websocket_message(flow: http.HTTPFlow):
    assert flow.websocket is not None  # make type checker happy
    # get the latest message
    message = flow.websocket.messages[-1]

    # was the message sent from the client or server?
    if message.from_client:
        logging.info(f"Client sent a message: {message.content!r}")
    else:
        logging.info(f"Server sent a message: {message.content!r}")

    # manipulate the message content
    message.content = re.sub(rb"^Hello", b"HAPPY", message.content)

    if b"FOOBAR" in message.content:
        # kill the message and not send it to the other endpoint
        message.drop()
```


## [anatomy(Addon)](https://docs.mitmproxy.org/stable/addons-examples/#anatomy)

```python
"""
Basic skeleton of a mitmproxy addon.

Run as follows: mitmproxy -s anatomy.py
"""

import logging


class Counter:
    def __init__(self):
        self.num = 0

    def request(self, flow):
        self.num = self.num + 1
        logging.info("We've seen %d flows" % self.num)


addons = [Counter()]
```


## [filter-flows](https://docs.mitmproxy.org/stable/addons-examples/#filter-flows)

```python
"""
Use mitmproxy's filter pattern in scripts.
"""

from __future__ import annotations

import logging

from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy.addonmanager import Loader


class Filter:
    filter: flowfilter.TFilter

    def configure(self, updated):
        if "flowfilter" in updated:
            self.filter = flowfilter.parse(".")

    def load(self, loader: Loader):
        loader.add_option("flowfilter", str, "", "Check that flow matches filter.")

    def response(self, flow: http.HTTPFlow) -> None:
        if flowfilter.match(self.filter, flow):
            logging.info("Flow matches filter:")
            logging.info(flow)


addons = [Filter()]
```


## [contentview](https://docs.mitmproxy.org/stable/addons-examples/#contentview)

## [options-simple.py](https://docs.mitmproxy.org/stable/addons-examples/#options-simple)

```python
    """
    Add a new mitmproxy option.

    Usage:

        mitmproxy -s options-simple.py --set addheader=true
    """

    from mitmproxy import ctx


    class AddHeader:
        def __init__(self):
            self.num = 0

        def load(self, loader):
            loader.add_option(
                name="addheader",
                typespec=bool,
                default=False,
                help="Add a count header to responses",
            )

        def response(self, flow):
            if ctx.options.addheader:
                self.num = self.num + 1
                flow.response.headers["count"] = str(self.num)
```

## [http-reply-from-proxy](https://docs.mitmproxy.org/stable/addons-examples/#http-reply-from-proxy)

```python
    """Send a reply from the proxy without sending the request to the remote server."""

    from mitmproxy import http


    def request(flow: http.HTTPFlow) -> None:
        if flow.request.pretty_url == "http://example.com/path":
            flow.response = http.Response.make(
                200,  # (optional) status code
                b"Hello World",  # (optional) content
                {"Content-Type": "text/html"},  # (optional) headers
            )
```

# [Example from community]()


## [Error hook](https://github.com/mitmproxy/mitmproxy/blob/main/examples/contrib/suppress_error_responses.py )

```python
    def error(self, flow: http.HTTPFlow):
        """Kills the flow if it has an error different to HTTPSyntaxException.
        Sometimes, web scanners generate malformed HTTP syntax on purpose and we do not want to kill these requests.
        """
        if flow.error is not None and not isinstance(flow.error, HttpSyntaxException):
            flow.kill()
```

## [Search regex pattern](https://github.com/mitmproxy/mitmproxy/blob/main/examples/contrib/search.py)

```python
    def _search(self, flows: Sequence[flow.Flow], regex: str) -> None:
        """
        Defines a command named "search" that matches
        the given regular expression against most parts
        of each request/response included in the selected flows.

        Usage: from the flow list view, type ":search" followed by
        a space, then a flow selection expression; e.g., "@shown",
        then the desired regular expression to perform the search.

        Alternatively, define a custom shortcut in keys.yaml; e.g.:
        -
          key: "/"
          ctx: ["flowlist"]
          cmd: "console.command search @shown "

        Flows containing matches to the expression will be marked
        with the magnifying glass emoji, and their comments will
        contain JSON-formatted search results.

        To view flow comments, enter the flow view
        and navigate to the detail tab.
        """
```

## [Websocket-replay](https://codeberg.org/KOLANICH-tools/wsreplay.py)

This interesting for testing purposes. Having a websocket replayer could avoid rate limits.

## [Remote-Debug](https://github.com/mitmproxy/mitmproxy/blob/main/examples/contrib/remote-debug.py)

Good tool to have for debugging. Allow to debug mitmproxy TUI with PyCharm


## [All markers](https://github.com/mitmproxy/mitmproxy/blob/main/examples/contrib/all_markers.py)

This could be used to create views on different aspects of the mitmproxy. One example could be create a WebSocket message view where only relevant/useful websocket flows are shown.

```python
@command.command("all.markers")
def all_markers():
    "Create a new flow showing all marker values"
    for marker in emoji.emoji:
        ctx.master.commands.call(
            "view.flows.create", "get", f"https://example.com/{marker}"
        )
        ctx.master.commands.call("flow.mark", [ctx.master.view[-1]], marker)
```