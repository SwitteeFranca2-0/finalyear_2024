from app import app

if __name__ == "__main__":
    from wsgiref.simple_server import make_server
    server = make_server('0.0.0.0', 8080, app)
    print("Serving on http://0.0.0.0:8080 ...")
    server.serve_forever()
