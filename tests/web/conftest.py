def pytest_addoption(parser):
    parser.addoption("--run-browser", action="store_true", help="Run real Chromium viewer tests")
    parser.addoption("--browser-executable", default=None, help="Optional existing Chromium executable")
    parser.addoption("--viewer-screenshots", default=None, help="Directory for viewer QA screenshots")
    parser.addoption("--live-graph", default=None, help="Optional local graph artifact for the live smoke test")
