# Vulnerable API Specification

This document describes the intentionally vulnerable API specification created for testing the security rule engine.

## Overview

The `vulnerable_api.yaml` specification contains 15 endpoints with various security vulnerabilities that demonstrate common API security issues.

## Vulnerabilities Detected

### 1. Admin Endpoint Exposure (8 findings)
**Endpoints Affected:**
- `GET /admin/config`
- `POST /admin/config`
- `GET /admin/users`
- `POST /admin/users`
- `GET /admin/export`

**Vulnerability:** Admin endpoints are accessible without proper authentication and authorization controls.

**Risk:** HIGH - Attackers can access administrative functions and sensitive data.

**Remediation:** Implement proper authentication (e.g., OAuth, JWT) and role-based access control (RBAC) for all admin endpoints.

### 2. Insecure Direct Object Reference (IDOR) (8 findings)
**Endpoints Affected:**
- `GET /users/{userId}`
- `PUT /users/{userId}`
- `DELETE /users/{userId}`
- `GET /users/{userId}/orders`
- `GET /users/{userId}/profile`

**Vulnerability:** Users can access, modify, or delete other users' data by manipulating user IDs in the URL.

**Risk:** CRITICAL - Complete compromise of user data privacy and integrity.

**Remediation:** Implement proper ownership checks to ensure users can only access their own data, use indirect object references, and implement proper authorization.

### 3. System Information Exposure (2 findings)
**Endpoints Affected:**
- `GET /system/info`

**Vulnerability:** System information endpoint exposes version details, server information, and other system-specific data.

**Risk:** MEDIUM - Aids attackers in fingerprinting and planning targeted attacks.

**Remediation:** Remove system information endpoints from production or restrict access to authorized administrators only.

### 4. Debug Endpoint Exposure (2 findings)
**Endpoints Affected:**
- `GET /debug/stacktrace`

**Vulnerability:** Debug endpoints are accessible in production, exposing stack traces and implementation details.

**Risk:** HIGH - Exposes internal implementation details that can aid attackers.

**Remediation:** Ensure debug endpoints are completely disabled or removed in production environments.

### 5. Data Export Exposure (2 findings)
**Endpoints Affected:**
- `GET /admin/export`

**Vulnerability:** Data export endpoint can export large amounts of sensitive data without proper access control.

**Risk:** CRITICAL - Could lead to massive data exfiltration.

**Remediation:** Implement strict access controls, audit logging, and approval workflows for data export operations.

### 6. Payment Processing Without Validation (1 endpoint)
**Endpoints Affected:**
- `POST /payments`

**Vulnerability:** Payment processing endpoint lacks proper security controls and validation.

**Risk:** CRITICAL - Financial fraud and payment processing vulnerabilities.

**Remediation:** Implement proper payment processing security, including PCI DSS compliance, input validation, and fraud detection.

## Secure Endpoints (For Comparison)

The following endpoints are considered secure and serve as baselines:
- `GET /products` - Public product listing
- `GET /products/{productId}` - Public product details

## Security Rule Coverage

The vulnerable API is tested against 6 security rules:

1. **admin_endpoint_check.yaml** - Detects exposed admin endpoints
2. **idor_check.yaml** - Detects insecure direct object references
3. **public_endpoint_check.yaml** - Verifies public endpoint availability
4. **system_info_check.yaml** - Detects system information exposure
5. **debug_endpoint_check.yaml** - Detects debug endpoint exposure
6. **data_export_check.yaml** - Detects data export vulnerabilities

## Test Results

Running the rule engine against the vulnerable API:

```bash
python3 python/main.py --rules ./rules --spec ./sample_specs/vulnerable_api.yaml --responses ./sample_specs/vulnerable_api_responses.yaml
```

**Results:** 28 potential vulnerabilities detected across 15 endpoints

## Severity Breakdown

- **CRITICAL:** 10 findings (IDOR, data export)
- **HIGH:** 12 findings (admin endpoints, debug endpoints)
- **MEDIUM:** 2 findings (system information)
- **INFO:** 2 findings (public endpoint validation)

## Usage in Testing

This vulnerable API specification is designed to:
1. Test the effectiveness of security rules
2. Demonstrate common API security vulnerabilities
3. Provide a realistic scenario for security testing
4. Help validate rule engine functionality

## Educational Purpose

This specification is created for educational and testing purposes only. It demonstrates common security mistakes that should be avoided in production APIs.