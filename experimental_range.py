#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, ssl, urllib.parse, html, sys, io
from http import HTTPStatus
from socketserver import ThreadingMixIn
from http.server import SimpleHTTPRequestHandler, HTTPServer, BaseHTTPRequestHandler

MYSERV_WORKDIR = "/media/kingdian/server_priv"
MYSERV_CLIENTCRT = "/home/ran/keys/client.pem"
MYSERV_FULLCHAIN = "/home/ran/keys/fullchain.pem"
MYSERV_PRIVKEY = "/home/ran/keys/privkey.pem"

global sslcontext
sslcontext = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
#sslcontext.options |= ssl.OP_NO_TLSv1
#sslcontext.options |= ssl.OP_NO_TLSv1_1
#sslcontext.options |= ssl.OP_NO_TLSv1_2
#sslcontext.protocol = ssl.PROTOCOL_TLS
sslcontext.verify_mode = ssl.CERT_REQUIRED
sslcontext.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305")
sslcontext.set_ecdh_curve("secp384r1")#works well with everything
#sslcontext.set_ecdh_curve("secp521r1")#works well on firefox and wget but not aria2
sslcontext.load_verify_locations(MYSERV_CLIENTCRT)
sslcontext.load_cert_chain(MYSERV_FULLCHAIN, MYSERV_PRIVKEY)

class HSTSHandler(SimpleHTTPRequestHandler):
    def send_head(self):
        path = self.translate_path(self.path)
        ctype = self.guess_type(path)
        if os.path.isdir(path):
            return CustomIndexer.list_directory(self, path)
        if not os.path.exists(path):
            return self.send_error(404, self.responses.get(404)[0])
        f = open(path, 'rb')
        fs = os.fstat(f.fileno())
        size = fs[6]
        start, end = 0, size - 1
        if 'Range' in self.headers:
            start, end = self.headers.get('Range').strip().strip('bytes=').split('-')
        if start == "":
            try:
                end = int(end)
            except ValueError as e:
                self.send_error(400, 'invalid range')
            start = size - end
        else:
            try:
                start = int(start)
            except ValueError as e:
                self.send_error(400, 'invalid range')
            if start >= size:
                self.send_error(416, self.responses.get(416)[0])
            if end == "":
                end = size - 1
            else:
                try:
                    end = int(end)
                except ValueError as e:
                    self.send_error(400, 'invalid range')
        start = max(start, 0)
        end = min(end, size - 1)
        self.range = (start, end)
        l = end - start + 1
        if 'Range' in self.headers:
            self.send_response(206)
        else:
            self.send_response(200)
        self.send_header('Content-type', ctype)
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Content-Range', 'bytes %s-%s/%s' % (start, end, size))
        self.send_header('Content-Length', str(l))
        self.send_header('Last-Modified', self.date_time_string(fs.st_mtime))
        self.end_headers()
        return f

    def copyfile(self, infile, outfile):
        if 'Range' not in self.headers:
            SimpleHTTPRequestHandler.copyfile(self, infile, outfile)
            return
        start, end = self.range
        infile.seek(start)
        bufsize = 64 * 1024
        remainder = (end - start) % bufsize
        times = int((end - start) / bufsize)
        steps = [bufsize] * times + [remainder]
        for astep in steps:
            buf = infile.read(bufsize)
            outfile.write(buf)
        return

    def end_headers(self):
        self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        #self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("Content-Security-Policy", "default-src 'none'; img-src 'self'; script-src 'self'; font-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Robots-Tag", "none")
        self.send_header("Permissions-Policy", "camera=(), microphone=()")
        self.send_header("Cross-Origin-Embedder-Policy", "unsafe-none")
        self.send_header("Cross-Origin-Opener-Policy", "unsafe-none")
        self.send_header("Cross-Origin-Resource-Policy", "cross-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        SimpleHTTPRequestHandler.end_headers(self)

HSTSHandler.extensions_map['.avif'] = 'image/avif'
HSTSHandler.extensions_map['.webp'] = 'image/webp'

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class CustomIndexer(SimpleHTTPRequestHandler):
    def list_directory(self, path):
        try:
            list = os.listdir(path)
        except OSError:
            self.send_error(
                HTTPStatus.NOT_FOUND,
                "No permission to list directory")
            return None
        list.sort(key=lambda a: a.lower())
        r = []
        try:
            displaypath = urllib.parse.unquote(self.path,
                                               errors='surrogatepass')
        except UnicodeDecodeError:
            displaypath = urllib.parse.unquote(path)
        displaypath = html.escape(displaypath, quote=False)
        enc = sys.getfilesystemencoding()
        title = 'Directory listing for %s' % displaypath
        r.append('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" '
                 '"http://www.w3.org/TR/html4/strict.dtd">')
        r.append('<html>\n<head>')
        r.append('<meta http-equiv="Content-Type" '
                 'content="text/html; charset=%s">' % enc)
        r.append('<title>%s</title>\n</head>' % title)
        r.append('<body>\n<h1>%s</h1>' % title)
        r.append('<hr>\n<ul>')
        for name in list:
            fullname = os.path.join(path, name)
            if os.path.isdir(fullname) == False:
                customname = "https://subdomain.domain.tld/someworkdir/" + urllib.parse.quote(name)
                r.append('<a href="%s">%s</a><br>'
                        % (customname,customname))
        r.append('</ul>\n<hr>\n</body>\n</html>\n')
        encoded = '\n'.join(r).encode(enc, 'surrogateescape')
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "text/html; charset=%s" % enc)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        return f

def main():
    try:
        os.chdir(MYSERV_WORKDIR)#auto-change working directory
        SimpleHTTPRequestHandler.sys_version = ""#empty version string
        SimpleHTTPRequestHandler.server_version = "nginx"#pretend to be nginx
        my_server = ThreadedHTTPServer(('0.0.0.0', 443), HSTSHandler)
        my_server.socket = sslcontext.wrap_socket(my_server.socket, do_handshake_on_connect=True, server_side=True)
        print('Starting server, use <Ctrl-C> to stop')
        my_server.serve_forever()
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, TimeoutError):
        pass
    except KeyboardInterrupt:
        print(' received, shutting down server')
        my_server.shutdown()

if __name__ == '__main__':
    main()
