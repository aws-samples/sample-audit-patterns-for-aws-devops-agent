# Lambda handler tests

Unit tests for the two Python functions in `lambda/`. The CDK tests in
`test/stack.test.ts` assert the synthesized template; these assert the code that
actually runs inside it.

```bash
pip install -r requirements-dev.txt
python -m pytest            # from this directory
```

Run them from this directory. `conftest.py` resolves the handler paths relative
to itself, and pytest adds the test directory to `sys.path` so `from conftest
import ...` resolves.

## Why the handlers are loaded by path

Both live in hyphenated directories (`journal-archiver`), which are not valid
module names, and both build their boto3 clients and read `os.environ` at import
time. `conftest.load_handler` stubs `boto3.client` and the environment *before*
executing the module from its file path. Each call returns a freshly executed
module, so no client state leaks between tests.

## What is covered

Behaviours a template assertion cannot see:

- **Pagination is followed.** Both APIs are server-paginated. A handler that
  read only the first page would archive a partial journal and still look
  healthy.
- **Redelivery does not create a second Object-Locked version.** EventBridge is
  at-least-once and the archive bucket is versioned with Object Lock, so an
  unconditional write would add a retention-locked version per delivery. The
  journal archiver relies on `IfNoneMatch='*'`; `PreconditionFailed` is the
  success path for a redelivery, not an error.
- **Content changing without a version bump still writes.** The recommendations
  poll compares the S3 ETag rather than testing existence, because the API
  permits content to mutate under the same version.
- **Failure isolation.** Task enrichment is best-effort and must not cost us the
  journal. One failed recommendation write must not abort the poll — but if
  every attempted write failed, that is systematic and must raise.
