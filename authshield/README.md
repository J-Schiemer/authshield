# 🛡️ authshield

A modular, framework-agnostic security suite providing FastAPI-compatible **Authentication**, **OAuth**, **CSRF Protection**, and **Session Management**.

`authshield` uses a dynamic factory architecture, allowing it to seamlessly inject secure, chainable configuration methods directly into `FastAPI` or any custom subclass wrapper you are already using—without breaking your existing inheritance tree or IDE autocomplete.

---

## 🚀 Features

* **Zero-Dependency-Inversion:** Extends your application class dynamically at runtime.
* **Fluent & Chainable API:** Configure your entire security stack in a single, elegant block.
* **Fully Modular:** Core engines (OAuth, CSRF, Sessions) are separated internally for clean maintainability.
* **Type Safe:** Built from the ground up to support PEP 561 standard inline type hints.

---

## 📦 Installation

Install `authshield` via `uv` (or your preferred package manager):

```bash
uv add authshield
```

---

## 🛠️ Quick Start

`authshield` provides a `shield_class` factory that wraps your application class (e.g., `FastAPI`) and injects fluent configuration methods like `.useOAuth()` and `.useAuth()`.

```python
from fastapi import FastAPI
from authshield import shield_class

# 1. Dynamically wrap your base application class
ShieldedApp = shield_class(FastAPI)

# 2. Instantiate and chain your security configuration seamlessly
app = (
    ShieldedApp(title="My Shielded API")
    .useOAuth(config={"client_id": "...", "client_secret": "..."})
    .useAuth(config={"secret_key": "..."})
)

@app.get("/")
async def root():
    return {"status": "shielded"}
```

---

## 📚 Advanced Architecture

### Stacking Custom Classes

Because `authshield` uses dynamic typing instead of a rigid subclass hierarchy, it plays nicely if you are already using a custom framework wrapper:

```python
class MyEnterpriseApp(FastAPI):
    def company_telemetry(self):
        pass

# authshield blends perfectly into your custom pipeline
SecuredApp = shield_class(MyEnterpriseApp)

app = SecuredApp()
app.company_telemetry() # Stays intact!
app.useAuth(...)        # Injected smoothly!
```

---

## 🗺️ Roadmap / Coming Soon

* [ ] Complete **CSRF Middleware Integration** (`.useCSRF()`)
* [ ] Server-side and Encrypted Client-side **Session Management**
* [ ] Argon2-cffi automated password hashing utilities
* [ ] OAuth2 support for **OAuth2.0** and **OpenID Connect**

---

## 📄 License

This project is licensed under the MIT License.
