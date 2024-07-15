import logging


def setup_logger():
    logger = logging.getLogger("DNSResolver")
    logger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler("dns_resolver.log")
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger
