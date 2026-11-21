# Importing these is what registers them. Skip it and every sync is a 500.
from api.integrations import (  # noqa: F401
    ai_bedrock,
    ai_connector,
    crowdstrike,
    fairtprm,
    guardicore,
    ldap,
    qualys,
    rapid7_appsec,
    rapid7_cloudsec,
    rapid7_insightvm,
    servicenow,
    splunk,
    zscaler,
)
from api.cloud import aws, azure, oci  # noqa: F401,E402  -- cloud exposure connectors register here too
