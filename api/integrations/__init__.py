# Importing these is what registers them. Skip it and every sync is a 500.
from api.integrations import (  # noqa: F401
    ai_connector,
    crowdstrike,
    fairtprm,
    guardicore,
    ldap,
    qualys,
    servicenow,
    splunk,
    zscaler,
)
