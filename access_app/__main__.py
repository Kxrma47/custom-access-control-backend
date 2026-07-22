from __future__ import annotations

from .api import create_server
from .settings import Settings


def main() -> None:
    settings = Settings.from_env()
    server = create_server(settings)
    address, port = server.server_address
    print(f"Server is running at http://{address}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
