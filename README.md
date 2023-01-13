# PrismTools

## Tools Included

### GoFuckery

Takes a Prism.json file and fixes/resolves the nessus reference links and also fixes CVSS:3.0 to CVSS:3.1

### NucleiImporter

Runs `nuclei` and maps the JSON output to a Prism-friendly format ready for importing

### HostRemove

The tool takes a file of IPs and removes them from the affected hosts of the issues. This is useful if you're on an internal infrastructure assessment and your local IP address is part of the scanned scope. This allows you to remove your own host from the results. If your host is the only one assigned to the issue then the issue will be deleted.

The hosts file should be a plaintext file with IPs on each line