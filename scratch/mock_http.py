import http.server
import socketserver

PORT = 8080

class MockHttpHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        html = (
            "<!DOCTYPE html>\n"
            "<html>\n"
            "<head><title>Local Mock HTTP Service</title></head>\n"
            "<body><h1>Hello World</h1></body>\n"
            "</html>\n"
        )
        self.wfile.write(html.encode('utf-8'))

    def log_message(self, format, *args):
        pass

if __name__ == '__main__':
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), MockHttpHandler) as httpd:
        print(f"[*] Serving mock HTTP on port {PORT}...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Stopping server.")
