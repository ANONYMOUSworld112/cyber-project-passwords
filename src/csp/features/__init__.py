"""Cybersecurity feature modules."""

from csp.features.vault import (
    add_credential,
    list_credentials,
    get_credential,
    update_credential,
    delete_credential,
    generate_password,
    search_credentials,
)
from csp.features.incidents import (
    add_incident,
    list_incidents,
    get_incident,
    update_incident,
    close_incident,
)
from csp.features.fim import (
    fim_baseline,
    fim_scan,
    fim_watch_add,
    fim_watch_remove,
    fim_watch_list,
)
from csp.features.hashdb import (
    hashdb_import,
    hashdb_lookup,
    hashdb_list_sources,
    hash_file,
)
from csp.features.logs import (
    logs_analyze,
    list_log_runs,
)

__all__ = [
    "add_credential",
    "list_credentials",
    "get_credential",
    "update_credential",
    "delete_credential",
    "generate_password",
    "search_credentials",
    "add_incident",
    "list_incidents",
    "get_incident",
    "update_incident",
    "close_incident",
    "fim_baseline",
    "fim_scan",
    "fim_watch_add",
    "fim_watch_remove",
    "fim_watch_list",
    "hashdb_import",
    "hashdb_lookup",
    "hashdb_list_sources",
    "hash_file",
    "logs_analyze",
    "list_log_runs",
]
