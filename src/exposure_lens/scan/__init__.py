"""Scan stage: offline host/URL rules + current open-service check (Shodan
InternetDB) + archived response-body reads (Wayback). Never contacts the target.
The body-reading engine (``bodyscan``) is also reused by the ``probe`` stage in
live-fetch mode."""
