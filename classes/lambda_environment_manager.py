import json
import logging
from datetime import datetime

from classes.environment_manager import EnvironmentManager
from classes.output_manager import OutputManager


class LambdaEnvironmentManager(EnvironmentManager):
    """
    EnvironmentManager variant for AWS Lambda.

    Differences from the CLI version:
      - Config comes from constructor parameters, not argparse / sys.argv.
      - Logs to stdout only (CloudWatch captures Lambda stdout automatically);
        no log file is created.
      - Evidence collection is disabled — dig/nslookup are not available in
        the Lambda runtime image by default.
      - extreme mode is disabled (IP range dumps are not useful in Lambda).
      - Output files are written to a local path (typically /tmp) and uploaded
        to S3 by the caller after run() completes.
    """

    def __init__(
        self,
        domains_file,
        output_dir,
        config_file="config.json",
        nameservers=None,
        max_threads=None,
        timeout=None,
        retries=None,
        verbose=False,
    ):
        # Initialise base attributes directly — do NOT call super().__init__()
        # because that triggers ConfigResolver / argparse, which has no meaning in Lambda.
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.domains = set()
        self.patterns = None
        self._config_file = config_file

        self.domains_file = domains_file
        self.verbose = verbose
        self.extreme = False
        self.nameservers = nameservers if nameservers else None
        self.max_threads = max_threads
        self.timeout = timeout
        self.retries = retries
        self.evidence = False  # dig/nslookup not available in Lambda runtime

        self.logger = self._setup_lambda_logger(verbose)
        self._load_config(config_file)
        self._apply_config_defaults()

        om = OutputManager(output_dir, self.timestamp, evidence=False)
        self.output_dir = om.output_dir
        self.output_files = om.output_files
        self.write_to_file = om.write_to_file

        self.environment_info = {
            "command_executed": "lambda",
            "external_ip": None,
            "run_in_docker": False,
        }
        self.save_environment_info()
        self.load_patterns()

        self.logger.info("LambdaEnvironmentManager initialized.")

    # ------------------------------------------------------------------
    # Lambda-specific helpers (not overrides of EnvironmentManager logic)
    # ------------------------------------------------------------------

    def _setup_lambda_logger(self, verbose=False):
        """Stdout-only logger — CloudWatch captures Lambda stdout automatically."""
        logger = logging.getLogger("DNSResolver")
        logger.setLevel(logging.INFO)
        if logger.hasHandlers():
            logger.handlers.clear()
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO if verbose else logging.WARNING)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        return logger

    def _load_config(self, config_file):
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                self.config = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            self.logger.warning("Could not load config file %s: %s", config_file, e)
            self.config = {}

    def _apply_config_defaults(self):
        config_args = self.config.get("config", {})
        if self.timeout is None:
            self.timeout = config_args.get("timeout")
        if self.retries is None:
            self.retries = config_args.get("retries")
        if self.max_threads is None:
            self.max_threads = config_args.get("max_threads", 50)

    # ------------------------------------------------------------------
    # Override: Lambda-specific formatting only
    # ------------------------------------------------------------------

    def log_effective_configuration(self):
        self.logger.info(
            "Lambda configuration: domains_file=%s output_dir=%s "
            "max_threads=%s timeout=%s retries=%s verbose=%s",
            self.domains_file,
            self.output_dir,
            self.max_threads,
            self.timeout,
            self.retries,
            self.verbose,
        )
