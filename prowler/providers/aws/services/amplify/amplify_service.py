from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class Amplify(AWSService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.apps = {}
        self.branches = {}
        self.__threading_call__(self._list_apps)
        self._list_tags_for_resource()
        self.__threading_call__(self._list_branches)

    def _list_apps(self, regional_client):
        logger.info("Amplify - Listing apps...")
        try:
            list_apps_paginator = regional_client.get_paginator("list_apps")
            for page in list_apps_paginator.paginate():
                for app in page.get("apps", []):
                    app_id = app.get("appId", "")
                    app_arn = app.get(
                        "appArn",
                        (
                            f"arn:{self.audited_partition}:amplify:"
                            f"{regional_client.region}:{self.audited_account}:"
                            f"apps/{app_id}"
                        ),
                    )
                    if not self.audit_resources or (
                        is_resource_filtered(app_arn, self.audit_resources)
                    ):
                        self.apps[app_arn] = AmplifyApp(
                            name=app.get("name", app_id),
                            app_id=app_id,
                            arn=app_arn,
                            region=regional_client.region,
                            environment_variables=app.get("environmentVariables", {}),
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: "
                f"{error}"
            )

    def _list_branches(self, regional_client):
        logger.info("Amplify - Listing branches...")
        try:
            for app in self.apps.values():
                if app.region != regional_client.region:
                    continue
                list_branches_paginator = regional_client.get_paginator(
                    "list_branches"
                )
                for page in list_branches_paginator.paginate(appId=app.app_id):
                    for branch in page.get("branches", []):
                        branch_name = branch.get("branchName", "")
                        branch_arn = branch.get(
                            "branchArn", f"{app.arn}/branches/{branch_name}"
                        )
                        if not self.audit_resources or (
                            is_resource_filtered(branch_arn, self.audit_resources)
                        ):
                            self.branches[branch_arn] = AmplifyBranch(
                                name=branch_name,
                                app_name=app.name,
                                app_id=app.app_id,
                                arn=branch_arn,
                                region=regional_client.region,
                                environment_variables=branch.get(
                                    "environmentVariables", {}
                                ),
                                tags=app.tags,
                            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: "
                f"{error}"
            )

    def _list_tags_for_resource(self):
        logger.info("Amplify - Listing tags...")
        try:
            for app in self.apps.values():
                try:
                    regional_client = self.regional_clients[app.region]
                    tags = regional_client.list_tags_for_resource(
                        resourceArn=app.arn
                    ).get("tags", {})
                    app.tags = [tags] if tags else []
                except Exception as error:
                    logger.error(
                        f"{app.region} -- "
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: "
                        f"{error}"
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: "
                f"{error}"
            )


class AmplifyApp(BaseModel):
    name: str
    app_id: str
    arn: str
    region: str
    environment_variables: Optional[dict] = {}
    tags: Optional[list] = []


class AmplifyBranch(BaseModel):
    name: str
    app_name: str
    app_id: str
    arn: str
    region: str
    environment_variables: Optional[dict] = {}
    tags: Optional[list] = []
