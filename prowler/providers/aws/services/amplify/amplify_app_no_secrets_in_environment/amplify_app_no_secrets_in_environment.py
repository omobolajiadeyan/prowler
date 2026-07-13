import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.amplify.amplify_client import amplify_client
from prowler.providers.aws.services.amplify.amplify_service import AmplifyBranch


class amplify_app_no_secrets_in_environment(Check):
    def execute(self):
        findings = []
        secrets_ignore_patterns = amplify_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = amplify_client.audit_config.get("secrets_validate", False)
        resources = list(amplify_client.apps.values()) + list(
            amplify_client.branches.values()
        )

        def resource_name(resource):
            if isinstance(resource, AmplifyBranch):
                return f"Amplify branch {resource.name} for app {resource.app_name}"
            return f"Amplify app {resource.name}"

        def payloads():
            for resource_index, resource in enumerate(resources):
                for var_index, (name, value) in enumerate(
                    (resource.environment_variables or {}).items()
                ):
                    yield (resource_index, var_index), json.dumps({name: value})

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads(), excluded_secrets=secrets_ignore_patterns, validate=validate
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for resource_index, resource in enumerate(resources):
            report = Check_Report_AWS(metadata=self.metadata(), resource=resource)
            display_name = resource_name(resource)
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in {display_name} environment variables."
            )
            secrets_found = []
            all_secrets = []
            environment_variables = resource.environment_variables or {}

            if scan_error and environment_variables:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan {display_name} environment variables for "
                    f"secrets: {scan_error}; manual review is required."
                )
                findings.append(report)
                continue

            for var_index, var_name in enumerate(environment_variables):
                detect_secrets_output = batch_results.get((resource_index, var_index))
                if detect_secrets_output:
                    all_secrets.extend(detect_secrets_output)
                    secrets_found.extend(
                        [
                            f"{secret['type']} in variable {var_name}"
                            for secret in detect_secrets_output
                        ]
                    )

            if secrets_found:
                report.status = "FAIL"
                report.status_extended = (
                    f"Potential secret found in {display_name} environment "
                    f"variables -> {', '.join(secrets_found)}."
                )
                annotate_verified_secrets(report, all_secrets)

            findings.append(report)

        return findings
