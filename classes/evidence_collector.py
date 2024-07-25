import asyncio
import platform
import subprocess
import os


class EvidenceCollector:
    def __init__(self, env_manager):
        self.env_manager = env_manager

    @staticmethod
    def check_tools_availability():
        """
        Check the availability of nslookup and dig tools in the system path.

        :return: Tuple indicating the availability of nslookup and dig (nslookup_available, dig_available).
        """
        if platform.system() == "Windows":
            nslookup_available = (
                subprocess.run(
                    ["where", "nslookup"], capture_output=True, text=True
                ).returncode
                == 0
            )
            dig_available = (
                subprocess.run(
                    ["where", "dig"], capture_output=True, text=True
                ).returncode
                == 0
            )
        else:
            nslookup_available = (
                subprocess.run(
                    ["which", "nslookup"], capture_output=True, text=True
                ).returncode
                == 0
            )
            dig_available = (
                subprocess.run(
                    ["which", "dig"], capture_output=True, text=True
                ).returncode
                == 0
            )

        return nslookup_available, dig_available

    async def save_and_log_dns_result(
        self, result, domain, nameserver, reason, evidence_dir, command_name
    ):
        """
        Save and log the result of a DNS query command.

        :param result: The subprocess result object.
        :param domain: The domain name queried.
        :param nameserver: The nameserver used for the query.
        :param reason: The reason for performing the query.
        :param evidence_dir: The directory to save the evidence file.
        :param command_name: The name of the DNS query command (e.g., nslookup, dig).
        :return: None
        """
        stdout, stderr = await result.communicate()
        content = stdout.decode() + "\n" + stderr.decode()
        filename = os.path.join(evidence_dir, f"{domain}_{reason}_{nameserver}.txt")
        await self.env_manager.write_to_file(filename, content)
        self.env_manager.log_info(
            f"{command_name} result saved for domain {domain} using nameserver {nameserver}"
        )

    async def perform_nslookup(self, domain, nameserver, reason, evidence_dir):
        """
        Perform a DNS lookup using the nslookup command and save the output to a file.

        :param domain: The domain name to query.
        :param nameserver: The nameserver to use for the query.
        :param reason: The reason for performing the query.
        :param evidence_dir: The directory to save the evidence file.
        :return: None
        """
        try:
            result = await asyncio.create_subprocess_exec(
                "nslookup",
                domain,
                nameserver,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await self.save_and_log_dns_result(
                result, domain, nameserver, reason, evidence_dir, "nslookup"
            )
        except Exception as e:
            self.env_manager.log_error(f"Command failed with error: {e}")
            raise e from None

    async def perform_dig(self, domain, nameserver, reason, evidence_dir):
        """
        Perform a DNS lookup using the dig command and save the output to a file.

        :param domain: The domain name to query.
        :param nameserver: The nameserver to use for the query.
        :param reason: The reason for performing the query.
        :param evidence_dir: The directory to save the evidence file.
        :return: None
        """
        try:
            result = await asyncio.create_subprocess_exec(
                "dig",
                f"@{nameserver}",
                domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await self.save_and_log_dns_result(
                result, domain, nameserver, reason, evidence_dir, "dig"
            )
        except Exception as e:
            self.env_manager.log_error(f"Command failed with error: {e}")
            raise e from None

    async def perform_dns_evidence(self, domain, nameserver, reason, evidence_dir):
        """
        Perform a DNS lookup using either nslookup or dig, depending on the system.

        :param domain: The domain name to perform the DNS lookup for.
        :param nameserver: The nameserver to use for the DNS lookup.
        :param reason: The reason for performing the DNS lookup.
        :param evidence_dir: The directory where the output file will be saved.
        :return: None
        """
        nslookup_available, dig_available = self.check_tools_availability()

        if platform.system() == "Windows":
            if nslookup_available:
                await self.perform_nslookup(domain, nameserver, reason, evidence_dir)
            else:
                self.env_manager.log_error(
                    f"nslookup not available on Windows system for domain {domain}"
                )
        else:
            if dig_available:
                await self.perform_dig(domain, nameserver, reason, evidence_dir)
            elif nslookup_available:
                await self.perform_nslookup(domain, nameserver, reason, evidence_dir)
            else:
                self.env_manager.log_error(
                    f"Neither dig nor nslookup available on non-Windows system for domain {domain}"
                )
