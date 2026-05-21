<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->

# libmcpguard

This directory is reserved for the future MCP eBPF Guard client library and
SDK. Code added here should be licensed under LGPL-2.1-or-later.

The client library / SDK boundary is intended for external programs that read
newline-delimited JSON events from the mcp-guard daemon over its Unix domain
socket.

GUI code must remain a separate program from the GPL-licensed core enforcement
engine. It should communicate with the core over the Unix domain socket / JSON
event protocol and must not directly link against or copy GPL core
implementation code unless the combined work is relicensed appropriately.
