#!/usr/bin/env python3
"""
Unit tests for CRAWL4AI_ALLOW_INSECURE_BIND security posture guard.
These tests verify that binding non-loopback without authentication
is blocked by default, but allowed with a warning when explicitly opted in.

To avoid environment import failures (missing project dependencies like PyOpenSSL/fastapi),
this test dynamically extracts and executes the target auth resolution functions
from server.py in a clean, controlled test environment.
"""

import sys
import os
import ast
import unittest
from unittest.mock import MagicMock, patch

# Locate paths
DOCKER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_PY_PATH = os.path.join(DOCKER_DIR, "server.py")

def load_auth_functions():
    """Extract _resolve_auth and _current_api_token function definitions from server.py using AST."""
    with open(SERVER_PY_PATH, "r", encoding="utf-8") as f:
        source = f.read()
    
    tree = ast.parse(source)
    nodes_to_extract = ["_resolve_auth", "_current_api_token"]
    extracted_source = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in nodes_to_extract:
            lines = source.splitlines()
            # node.lineno and node.end_lineno are 1-based
            func_lines = lines[node.lineno - 1 : node.end_lineno]
            extracted_source.append("\n".join(func_lines))
            
    if len(extracted_source) < 2:
        raise RuntimeError("Failed to extract target auth functions from server.py")
        
    return "\n\n".join(extracted_source)


class TestInsecureBind(unittest.TestCase):
    """Test runtime auth-posture guard under various host/auth/opt-out configurations."""

    def setUp(self):
        """Set up the mock namespace and execute the extracted auth functions within it."""
        self.original_env = dict(os.environ)

        # Mock dependencies
        self.mock_logger = MagicMock()
        self.mock_resolve_secret_key = MagicMock()
        
        # Test configuration dictionary
        self.config = {
            "app": {
                "host": "127.0.0.1"
            },
            "security": {
                "enabled": False,
                "jwt_enabled": False,
                "api_token": "",
                "allow_insecure_bind": False
            }
        }

        # Build clean execution namespace
        self.namespace = {
            "config": self.config,
            "os": os,
            "sys": sys,
            "logger": self.mock_logger,
            "resolve_secret_key": self.mock_resolve_secret_key,
        }

        # Load and execute the functions in the namespace
        auth_functions_code = load_auth_functions()
        exec(auth_functions_code, self.namespace)
        
        self.resolve_auth_fn = self.namespace["_resolve_auth"]

    def tearDown(self):
        """Restore original environment variables."""
        os.environ.clear()
        os.environ.update(self.original_env)

    def test_insecure_bind_refused_by_default(self):
        """Non-loopback bind without token or JWT must exit by default."""
        self.config["app"]["host"] = "0.0.0.0"
        self.config["security"]["jwt_enabled"] = False
        self.config["security"]["api_token"] = ""
        self.config["security"]["allow_insecure_bind"] = False
        
        if "CRAWL4AI_ALLOW_INSECURE_BIND" in os.environ:
            del os.environ["CRAWL4AI_ALLOW_INSECURE_BIND"]
        if "CRAWL4AI_API_TOKEN" in os.environ:
            del os.environ["CRAWL4AI_API_TOKEN"]

        with self.assertRaises(SystemExit) as cm:
            self.resolve_auth_fn()

        self.assertEqual(cm.exception.code, 1)
        self.mock_logger.critical.assert_called_once()
        self.assertIn("Refusing to start: binding %s with no CRAWL4AI_API_TOKEN", self.mock_logger.critical.call_args[0][0])
        self.assertEqual(self.mock_logger.critical.call_args[0][1], "0.0.0.0")

    def test_insecure_bind_allowed_via_env_true(self):
        """Non-loopback bind succeeds when CRAWL4AI_ALLOW_INSECURE_BIND=true."""
        self.config["app"]["host"] = "0.0.0.0"
        self.config["security"]["jwt_enabled"] = False
        self.config["security"]["api_token"] = ""
        self.config["security"]["allow_insecure_bind"] = False
        
        os.environ["CRAWL4AI_ALLOW_INSECURE_BIND"] = "true"
        if "CRAWL4AI_API_TOKEN" in os.environ:
            del os.environ["CRAWL4AI_API_TOKEN"]

        # Should not raise SystemExit
        self.resolve_auth_fn()
        
        self.mock_logger.warning.assert_called_once()
        self.assertIn("running unauthenticated on a non-loopback bind", self.mock_logger.warning.call_args[0][0])

    def test_insecure_bind_allowed_via_env_1(self):
        """Non-loopback bind succeeds when CRAWL4AI_ALLOW_INSECURE_BIND=1."""
        self.config["app"]["host"] = "0.0.0.0"
        self.config["security"]["jwt_enabled"] = False
        self.config["security"]["api_token"] = ""
        self.config["security"]["allow_insecure_bind"] = False
        
        os.environ["CRAWL4AI_ALLOW_INSECURE_BIND"] = "1"
        if "CRAWL4AI_API_TOKEN" in os.environ:
            del os.environ["CRAWL4AI_API_TOKEN"]

        # Should not raise SystemExit
        self.resolve_auth_fn()
        
        self.mock_logger.warning.assert_called_once()
        self.assertIn("running unauthenticated on a non-loopback bind", self.mock_logger.warning.call_args[0][0])

    def test_insecure_bind_allowed_via_config(self):
        """Non-loopback bind succeeds when security.allow_insecure_bind=True in config."""
        self.config["app"]["host"] = "0.0.0.0"
        self.config["security"]["jwt_enabled"] = False
        self.config["security"]["api_token"] = ""
        self.config["security"]["allow_insecure_bind"] = True
        
        if "CRAWL4AI_ALLOW_INSECURE_BIND" in os.environ:
            del os.environ["CRAWL4AI_ALLOW_INSECURE_BIND"]
        if "CRAWL4AI_API_TOKEN" in os.environ:
            del os.environ["CRAWL4AI_API_TOKEN"]

        # Should not raise SystemExit
        self.resolve_auth_fn()
        
        self.mock_logger.warning.assert_called_once()
        self.assertIn("running unauthenticated on a non-loopback bind", self.mock_logger.warning.call_args[0][0])

    def test_loopback_always_works_without_optout(self):
        """Loopback bind (127.0.0.1) always works, generating an ephemeral token."""
        self.config["app"]["host"] = "127.0.0.1"
        self.config["security"]["jwt_enabled"] = False
        self.config["security"]["api_token"] = ""
        self.config["security"]["allow_insecure_bind"] = False
        
        if "CRAWL4AI_ALLOW_INSECURE_BIND" in os.environ:
            del os.environ["CRAWL4AI_ALLOW_INSECURE_BIND"]
        if "CRAWL4AI_API_TOKEN" in os.environ:
            del os.environ["CRAWL4AI_API_TOKEN"]

        self.resolve_auth_fn()
        
        self.mock_logger.warning.assert_called_once()
        self.assertIn("generated an ephemeral token for this loopback session", self.mock_logger.warning.call_args[0][0])
        self.assertTrue(len(os.environ.get("CRAWL4AI_API_TOKEN", "")) > 0)

    def test_token_set_unaffected(self):
        """If CRAWL4AI_API_TOKEN is set, startup succeeds and new flag is ignored."""
        self.config["app"]["host"] = "0.0.0.0"
        self.config["security"]["jwt_enabled"] = False
        self.config["security"]["api_token"] = ""
        self.config["security"]["allow_insecure_bind"] = False
        
        os.environ["CRAWL4AI_API_TOKEN"] = "my-secret-token"
        if "CRAWL4AI_ALLOW_INSECURE_BIND" in os.environ:
            del os.environ["CRAWL4AI_ALLOW_INSECURE_BIND"]

        self.resolve_auth_fn()
        
        self.mock_logger.info.assert_called_once_with("Auth gate active (credential configured).")
        self.assertEqual(os.environ["CRAWL4AI_API_TOKEN"], "my-secret-token")

    def test_jwt_enabled_unaffected(self):
        """If jwt_enabled is True, startup succeeds and new flag is ignored."""
        self.config["app"]["host"] = "0.0.0.0"
        self.config["security"]["jwt_enabled"] = True
        self.config["security"]["api_token"] = ""
        self.config["security"]["allow_insecure_bind"] = False
        
        if "CRAWL4AI_API_TOKEN" in os.environ:
            del os.environ["CRAWL4AI_API_TOKEN"]
        if "CRAWL4AI_ALLOW_INSECURE_BIND" in os.environ:
            del os.environ["CRAWL4AI_ALLOW_INSECURE_BIND"]

        self.resolve_auth_fn()
        
        self.mock_logger.info.assert_called_once_with("Auth gate active (credential configured).")
        self.mock_resolve_secret_key.assert_called_once_with(required=True)

if __name__ == "__main__":
    unittest.main()
