#!/usr/bin/env python3
"""
run_server.py — Flask Server Entry Point

Starts the YARA RAG API server with optional configuration.

Usage:
    python run_server.py                    # Start on default port 5000
    python run_server.py --port 8000        # Custom port
    python run_server.py --model mistral    # Specific LLM model
    python run_server.py --debug             # Debug mode with auto-reload
    python run_server.py --prod             # Production mode
    
    # Combine options:
    python run_server.py --port 8000 --model mistral --debug

Options:
    --port PORT       Listen port (default: 5000)
    --model MODEL     LLM model: qwen, flan, mistral (default: qwen)
    --debug          Enable debug mode with auto-reload
    --prod           Production mode (no debug, no reload)
    --host HOST      Listen host (default: 0.0.0.0)
"""

import os
import sys
import argparse
from pathlib import Path

# Add project root to Python path
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

def main():
    """Parse arguments and start the server."""
    parser = argparse.ArgumentParser(
        description='Start YARA RAG Flask Server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Examples:\n'
               '  python run_server.py --port 8000\n'
               '  python run_server.py --model mistral --debug\n'
    )
    
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=5000,
        help='Listen port (default: 5000)'
    )
    
    parser.add_argument(
        '--host', '-H',
        default='0.0.0.0',
        help='Listen host (default: 0.0.0.0)'
    )
    
    parser.add_argument(
        '--model', '-m',
        choices=['qwen', 'flan', 'mistral'],
        default='qwen',
        help='LLM model (default: qwen)'
    )
    
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Enable debug mode with auto-reload'
    )
    
    parser.add_argument(
        '--prod',
        action='store_true',
        help='Production mode (no debug, no reload)'
    )
    
    args = parser.parse_args()
    
    # Set environment variables before importing server
    debug_mode = args.debug and not args.prod
    os.environ['FLASK_ENV'] = 'production' if args.prod else 'development'
    os.environ['FLASK_PORT'] = str(args.port)
    os.environ['DEFAULT_MODEL'] = args.model
    
    print("=" * 60)
    print("YARA RAG Generator — Flask Server")
    print("=" * 60)
    print(f"Host:           {args.host}:{args.port}")
    print(f"Model:          {args.model}")
    print(f"Environment:    {os.environ['FLASK_ENV']}")
    print(f"Debug Mode:     {debug_mode}")
    print("=" * 60)
    print("\nAPI Endpoints:")
    print("  GET    http://localhost:{}/health".format(args.port))
    print("  POST   http://localhost:{}/api/generate".format(args.port))
    print("  POST   http://localhost:{}/api/explain".format(args.port))
    print("  POST   http://localhost:{}/api/search".format(args.port))
    print("  GET    http://localhost:{}/api/stats".format(args.port))
    print("  POST   http://localhost:{}/api/benchmark".format(args.port))
    print("  POST   http://localhost:{}/api/model".format(args.port))
    print("\n" + "=" * 60)
    print("Starting server... (Press Ctrl+C to stop)")
    print("=" * 60 + "\n")
    
    # Import and run server
    from server import app
    
    app.run(
        host=args.host,
        port=args.port,
        debug=debug_mode,
        use_reloader=debug_mode,
        threaded=True
    )

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nServer stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)
