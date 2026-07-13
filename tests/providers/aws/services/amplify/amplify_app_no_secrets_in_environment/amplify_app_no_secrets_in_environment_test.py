from unittest import mock

from prowler.lib.utils.utils import SecretsScanError
from prowler.providers.aws.services.amplify.amplify_service import (
    AmplifyApp,
    AmplifyBranch,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


APP_NAME = "test-amplify-app"
APP_ID = "d123example"
APP_ARN = f"arn:aws:amplify:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:apps/{APP_ID}"
BRANCH_NAME = "main"
BRANCH_ARN = f"{APP_ARN}/branches/{BRANCH_NAME}"


class Test_amplify_app_no_secrets_in_environment:
    def test_no_apps_or_branches(self):
        amplify_client = mock.MagicMock
        amplify_client.apps = {}
        amplify_client.branches = {}
        amplify_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment.amplify_client",
                new=amplify_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment.detect_secrets_scan_batch",
                return_value={},
            ),
        ):
            from prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment import (
                amplify_app_no_secrets_in_environment,
            )

            check = amplify_app_no_secrets_in_environment()
            result = check.execute()

            assert len(result) == 0

    def test_app_without_environment_variables(self):
        amplify_client = mock.MagicMock
        amplify_client.apps = {
            APP_ARN: AmplifyApp(
                name=APP_NAME,
                app_id=APP_ID,
                arn=APP_ARN,
                region=AWS_REGION_US_EAST_1,
                tags=[],
            )
        }
        amplify_client.branches = {}
        amplify_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment.amplify_client",
                new=amplify_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment.detect_secrets_scan_batch",
                return_value={},
            ),
        ):
            from prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment import (
                amplify_app_no_secrets_in_environment,
            )

            check = amplify_app_no_secrets_in_environment()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Amplify app {APP_NAME} environment variables."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == APP_NAME
            assert result[0].resource_arn == APP_ARN
            assert result[0].resource_tags == []

    def test_app_with_non_secret_environment_variables(self):
        amplify_client = mock.MagicMock
        amplify_client.apps = {
            APP_ARN: AmplifyApp(
                name=APP_NAME,
                app_id=APP_ID,
                arn=APP_ARN,
                region=AWS_REGION_US_EAST_1,
                environment_variables={"PUBLIC_API_URL": "https://api.example.com"},
                tags=[],
            )
        }
        amplify_client.branches = {}
        amplify_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment.amplify_client",
                new=amplify_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment.detect_secrets_scan_batch",
                return_value={},
            ),
        ):
            from prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment import (
                amplify_app_no_secrets_in_environment,
            )

            check = amplify_app_no_secrets_in_environment()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Amplify app {APP_NAME} environment variables."
            )

    def test_app_with_secret_environment_variable(self):
        amplify_client = mock.MagicMock
        amplify_client.apps = {
            APP_ARN: AmplifyApp(
                name=APP_NAME,
                app_id=APP_ID,
                arn=APP_ARN,
                region=AWS_REGION_US_EAST_1,
                environment_variables={"db_password": "test-password"},
                tags=[],
            )
        }
        amplify_client.branches = {}
        amplify_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment.amplify_client",
                new=amplify_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment.detect_secrets_scan_batch",
                return_value={(0, 0): [{"type": "Secret Keyword"}]},
            ),
        ):
            from prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment import (
                amplify_app_no_secrets_in_environment,
            )

            check = amplify_app_no_secrets_in_environment()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in Amplify app {APP_NAME} environment variables -> Secret Keyword in variable db_password."
            )

    def test_branch_with_secret_environment_variable(self):
        amplify_client = mock.MagicMock
        amplify_client.apps = {}
        amplify_client.branches = {
            BRANCH_ARN: AmplifyBranch(
                name=BRANCH_NAME,
                app_name=APP_NAME,
                app_id=APP_ID,
                arn=BRANCH_ARN,
                region=AWS_REGION_US_EAST_1,
                environment_variables={"API_TOKEN": "ghp_example"},
                tags=[],
            )
        }
        amplify_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment.amplify_client",
                new=amplify_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment.detect_secrets_scan_batch",
                return_value={(0, 0): [{"type": "Secret Keyword"}]},
            ),
        ):
            from prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment import (
                amplify_app_no_secrets_in_environment,
            )

            check = amplify_app_no_secrets_in_environment()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in Amplify branch {BRANCH_NAME} for app {APP_NAME} environment variables -> Secret Keyword in variable API_TOKEN."
            )
            assert result[0].resource_id == BRANCH_NAME
            assert result[0].resource_arn == BRANCH_ARN

    def test_scanner_error_returns_manual(self):
        amplify_client = mock.MagicMock
        amplify_client.apps = {
            APP_ARN: AmplifyApp(
                name=APP_NAME,
                app_id=APP_ID,
                arn=APP_ARN,
                region=AWS_REGION_US_EAST_1,
                environment_variables={"db_password": "test-password"},
                tags=[],
            )
        }
        amplify_client.branches = {}
        amplify_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment.amplify_client",
                new=amplify_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment.detect_secrets_scan_batch",
                side_effect=SecretsScanError("scanner failed"),
            ),
        ):
            from prowler.providers.aws.services.amplify.amplify_app_no_secrets_in_environment.amplify_app_no_secrets_in_environment import (
                amplify_app_no_secrets_in_environment,
            )

            check = amplify_app_no_secrets_in_environment()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"Could not scan Amplify app {APP_NAME} environment variables for secrets: scanner failed; manual review is required."
            )
