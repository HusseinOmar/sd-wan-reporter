#!/usr/bin/env python3
"""
Stage 2 - SD-WAN configuration backup collection.

Wraps the underlying configuration backup engine behind a neutral interface.
Reuses an already-authenticated session (single login) so no second
authentication is performed. The generated backup archive is identical to the
one produced by running the underlying tool directly.
"""
import logging
import os

import requests


REST_TIMEOUT = 300


def _wrap_session_endpoints(session, endpoint_log):
    """Wrap a requests.Session's HTTP verb methods so each called URL is
    reported through endpoint_log."""
    for verb in ("get", "post", "put", "delete"):
        original = getattr(session, verb)

        def make_wrapper(_original):
            def wrapper(url, *args, **kwargs):
                try:
                    endpoint_log(url)
                except Exception:  # noqa: BLE001
                    pass
                return _original(url, *args, **kwargs)

            return wrapper

        setattr(session, verb, make_wrapper(original))


def _build_api(auth, timeout=REST_TIMEOUT, endpoint_log=None):
    """Construct an API client that reuses the existing authenticated session,
    bypassing a second login so the single token is reused. If endpoint_log is
    provided, each requested URL is reported through it.
    """
    from cisco_sdwan.base.rest_api import Rest

    session = requests.Session()
    session.headers.update(auth.header)
    if endpoint_log is not None:
        _wrap_session_endpoints(session, endpoint_log)

    api = Rest.__new__(Rest)
    api.base_url = auth.base_url
    api.timeout = timeout
    api.verify = False
    api.session = session
    api.server_facts = auth.server_facts
    api.is_tenant_scope = False
    api.use_apikey = False
    return api


def run(auth, archive_path, log=print, endpoint_log=None):
    """Run the Stage 2 configuration backup reusing the single session.

    @param auth: authenticated session holder (provides header, base_url, facts)
    @param archive_path: absolute path for the resulting backup zip archive
    @param log: callback for high-level status messages
    @param endpoint_log: callback invoked with each API endpoint URL used
    @return: absolute path to the backup zip archive
    """
    from cisco_sdwan.tasks.implementation._backup import BackupArgs, TaskBackup

    log("Starting Stage 2 collection ...")
    os.makedirs(os.path.dirname(archive_path), exist_ok=True)

    api = _build_api(auth, endpoint_log=endpoint_log)
    task = TaskBackup()
    backup_args = BackupArgs(archive=archive_path, tags=["all"])

    import argparse
    parsed_args = argparse.Namespace(**backup_args.model_dump())

    logging.getLogger("TaskBackup").setLevel(logging.INFO)

    try:
        task.runner(parsed_args, api)
    finally:
        try:
            api.logout()
        except Exception:  # noqa: BLE001 - logout failures are non-fatal
            pass
        try:
            api.session.close()
        except Exception:  # noqa: BLE001
            pass

    if not os.path.exists(archive_path):
        raise RuntimeError("Stage 2 collection did not produce an archive.")
    log("Stage 2 collection complete: %s" % os.path.basename(archive_path))
    return archive_path
