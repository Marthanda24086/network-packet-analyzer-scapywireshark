"""
Logging setup for NetScope.
"""

import logging
import sys


def setup_logging(level=logging.INFO):
    """Configures application-wide logging."""
    logger = logging.getLogger()
    logger.setLevel(level)

    # Console handler
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s',
        datefmt='%H:%M:%S'
    )
    handler.setFormatter(formatter)

    # Prevent duplicate handlers
    if not logger.handlers:
        logger.addHandler(handler)
