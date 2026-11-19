# Import all connector modules so their @register decorators fire at app startup.
# Without these imports the _REGISTRY stays empty and every get_connector() call
# raises ValueError, turning test/sync requests into 500s.
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
