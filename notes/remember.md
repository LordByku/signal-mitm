## List of reminders when something does not work

- __v2/keys/check__ this checks that server and client have the same view on the keys (reused). The naive solution is to return 200 (server to client) meaning (1) Drop the request, so it does not reach the real server, (2) the client will trust this response
