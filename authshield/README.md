# authshield

A modular, framework-agnostic security suite providing FastAPI-compatible **Authentication**, **CSRF Protection**, and **Session Management**.

`authshield` uses a dynamic factory architecture, allowing it to seamlessly inject secure, chainable configuration methods directly into `FastAPI` or any custom subclass wrapper you are already using -- without breaking your existing inheritance tree or IDE autocomplete.

---

## Features

* **Zero-Dependency-Inversion:** Extends your application class dynamically at runtime.
* **Fluent & Chainable API:** Configure your entire security stack in a single, elegant block.
* **Fully Modular:** Core engines (Auth, CSRF, Sessions) are separated internally for clean maintainability.
* **Type Safe:** Built from the ground up to support PEP 561 standard inline type hints.

---

## Installation

Install `authshield` via `uv` (or your preferred package manager):

```bash
uv add authshield
```

---

## Quick Start

`authshield` provides a `shield_class` factory that wraps your application class (e.g., `FastAPI`) and injects fluent configuration methods like `.useAuth()` and `.useCSRF()`.

```python
from fastapi import FastAPI
from authshield import shield_class

# 1. Dynamically wrap your base application class
ShieldedApp = shield_class(FastAPI)

# 2. Instantiate and chain your security configuration seamlessly
app = (
    ShieldedApp(title="My Shielded API")
    .useAuth(config={...})
    .useCSRF(config={...})
)

@app.get("/")
async def root():
    return {"status": "shielded"}
```

---

## Architecture

### Module Overview

```
authshield/
├── config.py           # CsrfConfig, AuthConfig, SsoConfig (Pydantic models)
├── extended.py         # shield_class() factory
├── auth/
│   ├── models.py       # UserSession, UserEntry, UserUpdate
│   ├── _auth_handler.py    # Password + SSO authentication logic
│   ├── _hashing.py         # Argon2id password hashing
│   ├── _require_auth.py    # FastAPI dependency for route protection
│   └── _use_auth.py        # Wires AuthConfig into app state
├── csrf/
│   ├── _csrf_handler.py    # CSRFMiddleware (Double-Submit Cookie)
│   └── _use_csrf.py        # Registers CSRF middleware
├── oauth/              # (planned)
└── session/            # (planned)
```

### Authentication

Two authentication flows are supported:

| Flow | Entry point | Description |
|------|-------------|-------------|
| **Password** | `authenticate_user(email, password, config)` | Verifies credentials via Argon2id hash and returns a `UserSession`. |
| **SSO** | `authenticate_user_by_sso(claims, config)` | Matches SSO claims to local users (by `sub` or email), with optional auto-merging and auto-provisioning. |

Route-level protection uses the `require_auth` FastAPI dependency:

```python
from fastapi import Depends
from authshield.auth import require_auth

@app.get("/me")
async def me(user=Depends(require_auth())):
    return user

@app.get("/admin")
async def admin(user=Depends(require_auth("admin", "superadmin"))):
    return user
```

### CSRF Protection

`CSRFMiddleware` implements the Double-Submit Cookie pattern with optional HMAC-signed token binding. Configure via `CsrfConfig`:

```python
from authshield.config import CsrfConfig

config = CsrfConfig(
    trusted_origins=["api.example.com", "app.example.com"],
    cookie_samesite="Strict",
    signed_mode=True,
    secret_key="your-secret-key",
)
```

### Configuration Models

| Model | Purpose |
|-------|---------|
| `CsrfConfig` | Cookie name, header, SameSite, trusted origins, signed mode |
| `AuthConfig` | SSO toggle, session cookie name, session resolver, user lookup |
| `SsoConfig` | SSO callbacks, auto-merging/provisioning, role mapping |

---

## Advanced Architecture

### Stacking Custom Classes

Because `authshield` uses dynamic typing instead of a rigid subclass hierarchy, it plays nicely if you are already using a custom framework wrapper:

```python
class MyEnterpriseApp(FastAPI):
    def company_telemetry(self):
        pass

# authshield blends perfectly into your custom pipeline
SecuredApp = shield_class(MyEnterpriseApp)

app = SecuredApp()
app.company_telemetry()  # Stays intact!
app.useAuth(...)         # Injected smoothly!
```

---

## Roadmap / Coming Soon

* [ ] Server-side and Encrypted Client-side **Session Management**
* [ ] OAuth2 support for **OAuth2.0** and **OpenID Connect**

---

## License

This project is licensed under the MIT License.
