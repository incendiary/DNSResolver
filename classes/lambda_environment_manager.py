import json
import logging
import os
from datetime import datetime

from classes.environment_manager import EnvironmentManager


class LambdaEnvironmentManager(EnvironmentManager):
    """
    EnvironmentManager variant for AWS Lambda.

    Differences from the CLI version:
      - Config comes from constructor parameters and environment variables,
        not argparse / sys.argv.
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
        # because that triggers argparse which has no meaning in Lambda.
        self.config = {}
        self.args = None
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.environment_info = {
            "command_executed": "lambda",
            "external_ip": None,
            "run_in_docker": False,
        }
        self.domains = set()
        self.patterns = None
        self.output_files = None
        self._config_file = config_file

        self.domains_file = domains_file
        self.output_dir = output_dir
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

        self.initialise_environment()
        self.save_environment_info()
        self.load_patterns()

        self.logger.info("LambdaEnvironmentManager initialized.")

    # ------------------------------------------------------------------
    # Overrides
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
        """Fill in any unset values from config.json."""
        config_args = self.config.get("config", {})
        if self.timeout is None:
            self.timeout = config_args.get("timeout")
        if self.retries is None:
            self.retries = config_args.get("retries")
        if self.max_threads is None:
            self.max_threads = config_args.get("max_threads", 50)

    def load_patterns(self):
        """Override to handle missing config file gracefully."""
        try:
            with open(self._config_file, "r", encoding="utf-8") as f:
                config = json.load(f)
            self.patterns = config.get("domain_categorisation", {})
        except (IOError, json.JSONDecodeError):
            self.patterns = {}

    def get_config_file(self):
        return self._config_file

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

    def save_environment_info(self):
        """Write environment JSON to the local output dir (will be uploaded to S3 by caller)."""
        env_path = self.output_files["standard"]["environment"]
        with open(env_path, "w", encoding="utf-8") as f:
            json.dump(self.environment_info, f, indent=4)
