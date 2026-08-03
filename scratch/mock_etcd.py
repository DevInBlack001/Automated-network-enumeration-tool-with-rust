import http.server
import socketserver
import json

PORT = 2379

class MockEtcdHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/version':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "etcdserver": "3.5.9",
                "etcdcluster": "3.5.0"
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
        elif self.path == '/v2/stats/self':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "name": "mock-etcd-node",
                "state": "StateLeader"
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
        elif self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            metrics = (
                "# HELP etcd_debugging_mvcc_db_total_size_in_bytes Total size of the db.\n"
                "# TYPE etcd_debugging_mvcc_db_total_size_in_bytes gauge\n"
                "etcd_debugging_mvcc_db_total_size_in_bytes 4096000\n"
            )
            self.wfile.write(metrics.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress logging to keep output clean
        pass

if __name__ == '__main__':
    # Allow port reuse
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), MockEtcdHandler) as httpd:
        print(f"[*] Serving mock etcd on port {PORT}...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Stopping server.")
