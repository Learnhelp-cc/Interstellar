# Security Policy

## Security Measures Implemented

Interstellar implements multiple layers of security to protect against common web application attacks:

### Authentication & Authorization

- **Password Encryption**: All passwords are encrypted using AES-256-GCM with PBKDF2 key derivation
- **Device Token Authentication**: Session-based authentication using cryptographically secure tokens
- **Admin Access Control**: Basic authentication for admin panel access
- **Account Approval System**: User accounts require admin approval before activation

### Input Validation & Sanitization

- **SQL Injection Protection**: Prepared statements used for all database operations
- **SQL Injection Detection**: Request middleware scans for suspicious SQL patterns
- **Input Validation**: Strict validation on user inputs, usernames, and passwords
- **File Upload Security**: Restricted to images only with size limits and mime-type validation

### Rate Limiting & Throttling

- **API Rate Limiting**: 100 requests per 15-minute window per IP address on API endpoints
- **Proxy Throttling**: Domain-based request throttling for proxy operations
- **Request Monitoring**: Tracking of suspicious activity and logging

### Security Headers & CSP

- **Content Security Policy**: Restrictive CSP allowing only necessary resources
- **HSTS**: HTTP Strict Transport Security headers
- **X-Content-Type-Options**: Prevents MIME type sniffing
- **X-Frame-Options**: Prevents clickjacking attacks
- **X-XSS-Protection**: XSS protection header

### Cross-Site Request Forgery (CSRF) Protection

- **CSRF Tokens**: Generated for API endpoints requiring state-changing operations
- **Token Validation**: Server-side validation of CSRF tokens

### CORS Policy

- **Restrictive Origins**: Limited to allowed origins to prevent unauthorized cross-origin requests

### Session Management

- **Secure Cookies**: HTTP-only, secure, same-site strict cookies
- **Fingerprinting**: Device fingerprinting for enhanced security
- **Token Expiration**: Automatic cleanup of expired tokens

### Network Security

- **Proxy Filtering**: Bare server with configurable remote filtering
- **WebSocket Security**: Authentication required for chat connections
- **SSH Protection**: Admin-only access to SSH terminal functionality

## Reporting Vulnerabilities

If you discover a security vulnerability in this project, please report it responsibly. We take security seriously and appreciate your help in keeping our users safe.

### How to Report

- **Do not** create public issues for security vulnerabilities.
- Email us at [security@learnhelp.cc](mailto:security@learnhelp.cc) with details of the vulnerability.
- Include as much information as possible, such as:
  - Description of the vulnerability
  - Steps to reproduce
  - Potential impact
  - Any suggested fixes

We will acknowledge your report within 48 hours and provide a more detailed response within 7 days indicating our next steps.

### Our Commitment

- We will investigate all legitimate reports.
- We will keep you informed about our progress.
- We will credit you (if desired) once the issue is resolved.
- We follow responsible disclosure practices.

Thank you for helping keep Interstellar secure!
