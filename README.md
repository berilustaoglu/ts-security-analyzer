# 🛡️ Type-Safe Security Log Parser & Threat Analyzer

A enterprise-grade TypeScript simulation engine designed to process SIEM/SOC infrastructure server logs using compile-time strict typing constraints.

## 🚀 Architectural Blueprint & TypeScript Features
- **Strict Data Contracts (`Interfaces`):** Enforces a permanent schema definition (`SecurityLog`) on structural event logs to protect against runtime schema drifts.
- **Typed Enums (`SeverityLevel`):** Eliminates hardcoded magic-strings by creating type-safe runtime severity matrices (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Encapsulated Scope Architecture:** Implements a type-protected Class wrapper (`ThreatAnalyzer`) with private state schemas to manage real-time payload evaluations.

## 💻 Technical Specification
- **Language:** TypeScript
- **Runtime Target:** Node.js (via `ts-node` or `tsc`)

## 🛠️ Compilation & Usage

1. Install global TypeScript compiler components:
```bash
npm install -g typescript ts-node
```

2. Execute the engine directly without explicit build cycles:
```bash
ts-node analyzer.ts
```
