# MCP eBPF Guard

Ultra-low overhead runtime security framework for MCP agents using eBPF.

## Overview

MCP eBPF Guard detects and controls dangerous behavior from local MCP agents, including unauthorized command execution, sensitive file access, and suspicious network connections.

## Architecture

- eBPF LSM hooks
- 3-tier TLB-hit modeled pipeline
- Lock-free epoch invalidation
- Ring buffer event delivery
- User-space GUI notification

## Features

- Detect dangerous command execution
- Monitor sensitive file access
- Send real-time GUI alerts
- Cache policy decisions using L1 fast path
- Invalidate cache with global epoch

## Repository Structure

...

## Build

```bash
make