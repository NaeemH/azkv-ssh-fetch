# Cassettes recorded by pytest-recording live here.
#
# Subdirectories are auto-created per test module: e.g.
#     tests/cassettes/test_keyvault_vcr/test_list_secrets_replays_recorded_call.yaml
#
# DO NOT commit a cassette without first opening it in an editor and confirming:
#
#   - Every "Authorization" header reads "REDACTED".
#   - Every "value" / "access_token" / "refresh_token" / "id_token" body field reads "REDACTED".
#   - No GUID other than 00000000-0000-0000-0000-000000000000 appears anywhere.
#   - The vault hostname is "test-vault.vault.azure.net" -- never the real one.
#
# The scrubbers in tests/conftest.py do this automatically, but the human
# eyeball is the actual safety mechanism. See the recording workflow in README.
