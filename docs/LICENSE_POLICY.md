<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# License Policy

MCP eBPF Guard uses component-level licensing.

The core enforcement engine is licensed under GPL-2.0-or-later to ensure that
distributed modifications to the kernel/eBPF enforcement path remain open. This
includes the BPF programs, loader, policy enforcement code, core headers,
tests, benchmarks, experiments, scripts, and policy files.

Client libraries and SDKs are licensed under LGPL-2.1-or-later so external
tools can integrate with the mcp-guard daemon while improvements to the shared
client library remain open. This applies to `libmcpguard/`, `sdk/`, `clients/`,
and `include/client/` when those components exist.

The GUI and operator dashboard are licensed under AGPL-3.0-or-later to preserve
source availability for modified dashboard deployments, including networked or
remote operator environments. This applies to desktop GUI code, web dashboards,
operator consoles, and related UI assets.

Documentation, diagrams, papers, and presentation materials are licensed under
CC-BY-4.0. This includes `docs/`, `paper/`, `figures/`, `presentations/`,
slides, and documentation-oriented images.

The core daemon and GUI are separate programs and communicate over a Unix
domain socket using newline-delimited JSON events. The GUI must not directly
link against GPL-only core implementation code or copy GPL core implementation
into the GUI unless the combined work is relicensed appropriately.

The BPF object declaration `char LICENSE[] SEC("license") = "GPL"` is
kernel-facing metadata used by the Linux BPF verifier and helper compatibility
logic. It does not override the SPDX license headers of repository files.

When adding new files, apply the license for the component that owns the file:

- Use GPL-2.0-or-later for core enforcement, BPF, loader, policy, test,
  benchmark, experiment, and operational script files.
- Use LGPL-2.1-or-later for client libraries, SDKs, and public client-facing
  integration code.
- Use AGPL-3.0-or-later for GUI, dashboard, operator console, and remote UI
  files.
- Use CC-BY-4.0 for documentation, diagrams, papers, slides, and presentation
  material.

If a new file does not cleanly fit one of these categories, document the choice
in the commit or pull request and keep the component boundary explicit.
