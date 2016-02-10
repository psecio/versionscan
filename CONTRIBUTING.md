# Contributing

Contributions are **welcome** and will be fully **credited**.

We accept contributions via Pull Requests on [GitHub](https://github.com/psecio/versionscan).

## Adding CVEs

New CVEs should be added to `src/Psecio/Versionscan/checks.json`.  Refer to the existing checks to see how to format them.  Some guidlines:

 - CVEs should be sorted in ascending order by their CVE ID.
   - For example, `CVE-2000-0967` would go after `CVE-2000-0860` but before `CVE-2001-0108`.
 - For each minor version affected by the CVE, add a new string to `fixVersions` -> `base` containing the version where the issue is resolved.
   - For example, if the issue affects 5.3.12 and 5.4.9, add `"5.3.13"` and `"5.4.10`"
   - These versions should also be sorted in ascending order

