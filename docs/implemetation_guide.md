# Implementation & Setup Guide

## Keycloak-based Authentication & Authorization Service

This guide explains how to set up and run the authentication platform
locally.

The system includes:

-   Backend authentication service
-   Frontend application
-   Keycloak Identity Provider
-   PostgreSQL database
-   MailHog SMTP testing server

------------------------------------------------------------------------

# 1. Clone the Repositories

Clone both the backend and frontend repositories.

## Backend Repository

``` bash
git clone https://github.com/HDFC-AS03/AS-03-Backend.git
```

## Frontend Repository

``` bash
git clone https://github.com/HDFC-AS03/AS-03-Frontend.git
```

------------------------------------------------------------------------

# 2. Setup Backend Environment

Navigate to the backend directory.

``` bash
cd AS-03-Backend
```

Create a Python virtual environment.

``` bash
python -m venv venv
```

Activate the virtual environment.

### Windows

``` bash
venv\Scripts\activate
```

### Linux / Mac

``` bash
source venv/bin/activate
```

Install dependencies.

``` bash
pip install -r requirements.txt
```

------------------------------------------------------------------------

# 3. Configure Environment Variables

An environment template file (`.env.example`) is included in the
repository.

Create a `.env` file from the template.

``` bash
cp .env.example .env
```

Update the `.env` file with the required configuration values.

Key variables include:

    KEYCLOAK_CLIENT_ID
    KEYCLOAK_CLIENT_SECRET
    KEYCLOAK_ADMIN_CLIENT_ID
    KEYCLOAK_ADMIN_CLIENT_SECRET
    KEYCLOAK_REALM
    KEYCLOAK_SERVER_URL
    FRONTEND_URL
    SESSION_SECRET_KEY

These secrets will be obtained from Keycloak in later steps.

------------------------------------------------------------------------

# 4. Start Infrastructure Services

The project includes a Docker Compose configuration to start the
required infrastructure services:

-   Keycloak
-   PostgreSQL
-   MailHog (SMTP testing server)

Run the following command from the backend project directory:

``` bash
docker compose up -d
```

This will start:

  Service      Port          Purpose
  ------------ ------------- -------------------
  Keycloak     8080          Identity provider
  PostgreSQL   5432          Keycloak database
  MailHog      8025 / 1025   Email testing

------------------------------------------------------------------------

# 5. Verify Infrastructure Services

Ensure that all services are running.

``` bash
docker ps
```

Expected containers:

    keycloak
    postgres
    mailhog

Access services:

  Service      URL
  ------------ -----------------------
  Keycloak     http://localhost:8080
  MailHog UI   http://localhost:8025

------------------------------------------------------------------------

# 6. Configure Keycloak

Open Keycloak in a browser:

    http://localhost:8080

Login using:

    Username: admin
    Password: admin

------------------------------------------------------------------------

# 7. Configure the Realm

Inside Keycloak:

1.  Select the **auth-realm**
2.  Navigate to **Clients**
3.  Locate:

```{=html}
```
    fastapi-app
    fast-api-admin-client

------------------------------------------------------------------------

# 8. Regenerate Client Secrets

For both clients:

1.  Open the client
2.  Go to **Credentials**
3.  Click **Regenerate Secret**
4.  Copy the generated secret

Update your `.env` file:

    KEYCLOAK_CLIENT_SECRET=<fastapi-app-secret>
    KEYCLOAK_ADMIN_CLIENT_SECRET=<fast-api-admin-client-secret>

------------------------------------------------------------------------

# 9. Verify User Pool

Navigate to:

    Keycloak → auth-realm → Users

This is the user pool managed by the system.

Administrators can:

-   View users
-   Create users
-   Assign roles
-   Manage credentials

------------------------------------------------------------------------

# 10. Start Backend Authentication Service

Run:

``` bash
uvicorn app.main:app --reload --host localhost --port 8000
```

Backend runs at:

    http://localhost:8000

------------------------------------------------------------------------

# 11. Start the Frontend Application

Navigate to frontend repository:

``` bash
cd AS-03-Frontend
```

Install dependencies:

``` bash
npm install
```

Start development server:

``` bash
npm run dev
```

Frontend runs at:

    http://localhost:5173

------------------------------------------------------------------------

# 12. Login Flow Verification

Open:

    http://localhost:5173

Click **Login**.

Authentication flow:

    Frontend → Auth Service → Keycloak → Auth Service → Frontend

After login, the user is redirected to the dashboard.

------------------------------------------------------------------------

# 13. Email Testing with MailHog

MailHog UI:

    http://localhost:8025

Emails such as:

-   verification emails
-   password setup emails
-   notifications

will appear here.

------------------------------------------------------------------------

# 14. API Endpoints

The backend authentication service exposes the following APIs.

## Public Endpoints

  Method   Endpoint   Description
  -------- ---------- ---------------
  GET      /          Root endpoint
  GET      /health    Health check

------------------------------------------------------------------------

## Authentication Endpoints

  Method   Endpoint    Description
  -------- ----------- ----------------------------
  GET      /login      Redirect to Keycloak login
  GET      /callback   OAuth2 callback
  GET      /logout     Logout user
  POST     /refresh    Refresh access token

------------------------------------------------------------------------

## User Endpoints

  Method   Endpoint   Description
  -------- ---------- -------------------------------------------
  GET      /me        Get current authenticated user
  GET      /account   Redirect to Keycloak user account console

------------------------------------------------------------------------

## Admin Endpoints

  Method   Endpoint                 Description
  -------- ------------------------ ------------------------------------
  GET      /admin                   Admin access test
  GET      /admin/console           Redirect to Keycloak admin console
  POST     /admin/bulk-users        Bulk create users
  GET      /admin/users             View users by role
  DELETE   /admin/users/{user_id}   Delete user

------------------------------------------------------------------------

## Role Management APIs

  Method   Endpoint                       Description
  -------- ------------------------------ -------------
  POST     /admin/users/{user_id}/roles   Assign role
  DELETE   /admin/users/{user_id}/roles   Remove role
  PUT      /admin/users/{user_id}/roles   Update role

------------------------------------------------------------------------


# 15. Stopping the System

Stop all services:

``` bash
docker compose down
```

Remove containers and volumes:

``` bash
docker compose down -v
```

------------------------------------------------------------------------

# Final Notes

This setup provides a local development environment including:

-   Keycloak IAM
-   FastAPI authentication gateway
-   RBAC authorization
-   Email verification testing
-   Admin user management
-   Monitoring support
