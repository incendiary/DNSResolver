import logging
import os

import aiofiles


class OutputManager:
    """Creates the output directory structure and handles async file writes."""

    def __init__(self, base_output_dir, timestamp, evidence=False):
        self._logger = logging.getLogger("DNSResolver")
        self.output_dir = os.path.join(base_output_dir, timestamp)
        os.makedirs(self.output_dir, exist_ok=True)
        self.output_files = self._build_output_files(timestamp, evidence)
        self._create_all()

    def _build_output_files(self, timestamp, evidence):
        d = self.output_dir
        files = {
            "standard": {
                "resolved": os.path.join(d, f"resolution_results_{timestamp}.txt"),
                "unresolved": os.path.join(d, f"unresolved_results_{timestamp}.txt"),
                "gcp": os.path.join(d, f"gcp_results_{timestamp}.txt"),
                "aws": os.path.join(d, f"aws_results_{timestamp}.txt"),
                "azure": os.path.join(d, f"azure_results_{timestamp}.txt"),
                "dangling": os.path.join(d, f"dangling_cname_results_{timestamp}.txt"),
                "ns_takeover": os.path.join(d, f"ns_takeover_results_{timestamp}.txt"),
                "environment": os.path.join(d, f"environment_results_{timestamp}.json"),
                "timeout": os.path.join(d, f"timeout_results_{timestamp}.txt"),
            }
        }
        if evidence:
            files["evidence"] = {"dns": os.path.join(d, "evidence", "dns")}
        return files

    def _create_all(self):
        for path in self.output_files.get("standard", {}).values():
            self._create(path)
        if "evidence" in self.output_files:
            for path in self.output_files["evidence"].values():
                self._create(path)

    def _create(self, path):
        _, ext = os.path.splitext(path)
        try:
            if not ext:
                os.makedirs(path, exist_ok=True)
            else:
                with open(path, "w", encoding="utf-8"):
                    pass
        except (IOError, OSError) as e:
            self._logger.error("Unable to create %s: %s", path, e)

    async def write_to_file(self, file_path, content):
        try:
            async with aiofiles.open(file_path, "a", encoding="utf-8") as f:
                await f.write(content + "\n")
        except Exception as e:
            self._logger.error("Failed to write to %s: %s", file_path, e)
