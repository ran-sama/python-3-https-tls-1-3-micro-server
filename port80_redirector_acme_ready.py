#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
from socketserver import ThreadingMixIn
from http.server import SimpleHTTPRequestHandler, HTTPServer

MYSERV_ACMEWEBDIR = "/home/ran/.acmeweb"

class RedirectHandler(SimpleHTTPRequestHandler):
    def do_HEAD(self):
        if self.path.startswith("/.well-known"):#only serve acme challenges
            SimpleHTTPRequestHandler.do_HEAD(self)
        else:
            self.send_response(301)#redirect all other requests
            self.send_header("Location", "https://example.com/")
            self.send_header("Content-Length", "0")
            SimpleHTTPRequestHandler.end_headers(self)

    def do_GET(self):
        if self.path.startswith("/.well-known"):#only serve acme challenges
            SimpleHTTPRequestHandler.do_GET(self)
        else:
            self.send_response(301)#redirect all other requests
            self.send_header("Location", "https://example.com/")
            self.send_header("Content-Length", "0")
            SimpleHTTPRequestHandler.end_headers(self)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

def main():
    try:
        os.chdir(MYSERV_ACMEWEBDIR)#auto-change working directory
        SimpleHTTPRequestHandler.server_version = "nginx"#pretend to be nginx
        SimpleHTTPRequestHandler.sys_version = ""#empty version string
        server = ThreadedHTTPServer(('0.0.0.0', 80), RedirectHandler)
        print("Starting server, use <Ctrl-C> to stop")
        server.serve_forever()

    except KeyboardInterrupt:
        print(" received, shutting down server")
        server.shutdown()

if __name__ == '__main__':
    main()
