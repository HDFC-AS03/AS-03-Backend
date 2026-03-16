<<<<<<< HEAD
# Mywallet — Keycloak Custom Theme

A clean, modern Keycloak login/logout theme for the **Mywallet** personal wallet application. Built with inline CSS and FreeMarker templates, requiring no build tools or external dependencies beyond a Google Fonts import.

---

## Files

| File | Description |
|------|-------------|
| `login.ftl` | Custom login page (replaces Keycloak's default) |
| `logout-confirm.ftl` | Custom logout confirmation page |

---

## Design

Both pages share a consistent visual identity:

- **Font:** [Poppins](https://fonts.google.com/specimen/Poppins) (400–800 weight) via Google Fonts
- **Primary colour:** `#5046e5` (indigo/purple)
- **Accent colour:** `#3b67f8` (blue)
- **Background:** `#f0f2f5` (light grey)
- **Layout:** Two-column split — SVG illustration on the left, action card on the right
- **Responsive:** Illustration is hidden on screens ≤ 768px; card goes full-width

### Login page (`login.ftl`)
- Locked padlock SVG illustration with `SECURE` badge
- Email/username field with envelope icon
- Password field with show/hide toggle (uses Keycloak's `passwordVisibility.js`)
- Remember me checkbox and Forgot password link (conditionally rendered based on realm settings)
- Social provider icons for Google and GitHub (conditionally rendered)
- Registration link in the `info` section

### Logout page (`logout-confirm.ftl`)
- Open/unlocked padlock SVG illustration with `SEE YOU` badge
- Confirmation card with logout icon, message, and confirm button
- Optional "Back to application" link (rendered only when `client.baseUrl` is set and `logoutConfirm.skipLink` is false)

---

## Docker Setup (Recommended)

This is the easiest and most reliable way to use this theme with a Dockerised Keycloak instance.

### Project folder structure

Set up your project like this on your local machine:

```
my-project/
├── docker-compose.yml
└── themes/
    └── mywallet/
        └── login/
            ├── theme.properties
            ├── login.ftl
            └── logout-confirm.ftl
```

### `theme.properties`

Create `themes/mywallet/login/theme.properties`:

```properties
parent=keycloak
import=common/keycloak
kcFormPasswordVisibilityIconShow=fa fa-eye
kcFormPasswordVisibilityIconHide=fa fa-eye-slash
```

### `docker-compose.yml`

Mount your local `themes/` folder into the container using a volume:

```yaml
version: "3"

services:
  keycloak:
    image: quay.io/keycloak/keycloak:latest
    command: start-dev
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
      KC_HTTP_PORT: 8080
    volumes:
      - ./themes:/opt/keycloak/themes   # <-- mounts your theme folder
    ports:
      - "8080:8080"
```

> The path inside the container is always `/opt/keycloak/themes`. Your local `themes/` folder maps directly to it, so Keycloak will see `mywallet` as an available theme.

### Start the container

```bash
docker-compose up
```

Keycloak will be available at `http://localhost:8080`.

---

## Activate the Theme in Keycloak Admin Console

1. Open `http://localhost:8080` and go to **Administration Console**
2. Log in with `admin` / `admin` (or your configured credentials)
3. Select your **realm** from the top-left dropdown
4. Go to **Realm Settings** → **Themes** tab
5. Set **Login theme** to `mywallet`
6. Click **Save**
7. Open a new incognito window and visit your realm's login page to see the new theme

---

## Disable Theme Cache During Development

By default Keycloak caches theme files, so edits to `.ftl` files won't show up until you restart the container. Disable caching for live reloads by adding these environment variables to your `docker-compose.yml`:

```yaml
environment:
  KEYCLOAK_ADMIN: admin
  KEYCLOAK_ADMIN_PASSWORD: admin
  KC_HTTP_PORT: 8080
  KC_THEME_CACHE_THEMES: "false"       # disables theme file caching
  KC_THEME_CACHE_TEMPLATES: "false"    # disables FTL template caching
```

With caching off, just save your `.ftl` file and **reload the browser** — no container restart needed.

> ⚠️ Re-enable caching in production (`true` or remove the lines entirely) as disabled caching significantly impacts performance.

---

## Alternative: Copy Files Directly Into a Running Container

If you already have Keycloak running in Docker and don't want to use volumes, you can copy the theme files directly into the container.

**Step 1 — Find your container ID or name:**

```bash
docker ps
```

Look for the Keycloak container in the output. Note the value in the `CONTAINER ID` or `NAMES` column, for example `a3f9c12d88e1` or `keycloak`.

**Step 2 — Create the theme directory inside the container:**

```bash
docker exec <container_id> mkdir -p /opt/keycloak/themes/mywallet/login
```

**Step 3 — Copy your files in:**

```bash
docker cp themes/mywallet/login/login.ftl          <container_id>:/opt/keycloak/themes/mywallet/login/
docker cp themes/mywallet/login/logout-confirm.ftl <container_id>:/opt/keycloak/themes/mywallet/login/
docker cp themes/mywallet/login/theme.properties   <container_id>:/opt/keycloak/themes/mywallet/login/
```

**Step 4 — Restart the container so Keycloak picks up the new theme:**

```bash
docker restart <container_id>
```

> ⚠️ Files copied this way are **not persistent** — they will be lost if the container is recreated. Use the volume mount approach above for anything beyond a quick test.

---

## Alternative: Bake the Theme Into a Custom Docker Image (Production)

For production deployments, the most reliable approach is to build the theme directly into a custom Docker image so there are no external file dependencies at runtime.

**`Dockerfile`:**

```dockerfile
FROM quay.io/keycloak/keycloak:latest

# Copy the entire theme into the image
COPY themes/mywallet /opt/keycloak/themes/mywallet

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
```

**Build and run:**

```bash
docker build -t mywallet-keycloak .

docker run \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -p 8080:8080 \
  mywallet-keycloak start-dev
```

This approach bundles the theme inside the image — no volume mounts, no file copying, no risk of files disappearing on container recreate.

---

## Where Are the Default Theme Files?

If you need to reference or copy the original Keycloak `.ftl` files (e.g. `template.ftl`, `register.ftl`, etc.), they are packed inside a JAR inside the container. Extract them like this:

```bash
# 1. Get the running container ID
docker ps

# 2. Find the themes JAR filename
docker exec <container_id> sh -c "ls /opt/keycloak/lib/lib/main/ | grep 'keycloak-themes'"

# 3. Copy the JAR to your local machine
docker cp <container_id>:/opt/keycloak/lib/lib/main/<themes-jar-name>.jar ./keycloak-themes.jar

# 4. Extract it
unzip keycloak-themes.jar -d keycloak-default-themes
```

The default `login.ftl`, `template.ftl`, `logout-confirm.ftl` and all other pages will be inside `keycloak-default-themes/theme/keycloak/login/`.

---

## Keycloak Variable Reference

Every FreeMarker variable used across both template files:

| Variable | File | Purpose |
|----------|------|---------|
| `url.loginAction` | `login.ftl` | Form POST action URL |
| `url.loginResetCredentialsUrl` | `login.ftl` | Forgot password link |
| `url.registrationUrl` | `login.ftl` | Register link |
| `url.resourcesPath` | `login.ftl` | Path to theme JS/CSS resources |
| `messagesPerField.existsError()` | `login.ftl` | Inline field error state |
| `messagesPerField.getFirstError()` | `login.ftl` | Error message text |
| `realm.password` | `login.ftl` | Whether password login is enabled |
| `realm.rememberMe` | `login.ftl` | Show/hide remember me checkbox |
| `realm.resetPasswordAllowed` | `login.ftl` | Show/hide forgot password link |
| `realm.registrationAllowed` | `login.ftl` | Show/hide register link |
| `social.providers` | `login.ftl` | List of social login providers |
| `login.username` | `login.ftl` | Pre-fill username field |
| `login.rememberMe` | `login.ftl` | Pre-check remember me box |
| `auth.selectedCredential` | `login.ftl` | Hidden credential input value |
| `url.logoutConfirmAction` | `logout-confirm.ftl` | Logout form POST action URL |
| `logoutConfirm.code` | `logout-confirm.ftl` | Session code for the logout request |
| `logoutConfirm.skipLink` | `logout-confirm.ftl` | Whether to hide the back-to-app link |
| `client.baseUrl` | `logout-confirm.ftl` | Back to application URL |

---

## Customisation

### Changing the brand name or tagline
In `login.ftl`, find and edit:
```html
<p class="mw-welcome">Welcome to</p>
<h1 class="mw-brand">Mywallet</h1>
<p class="mw-tagline">A personal wallet</p>
```

### Changing colours
Search and replace these tokens across both files:

| Token | Default | Role |
|-------|---------|------|
| `#5046e5` | Indigo | Primary brand, borders, labels |
| `#3b67f8` | Blue | Button, accents |
| `#f0f2f5` | Light grey | Page background |
| `#ebebef` | Light grey | Input field background |

### Adding more social providers
In the `socialProviders` section of `login.ftl`, add a new `<#case>` block inside the `<#switch p.alias>` statement with your provider's SVG icon.

---

## Notes

- The layout wrappers (`#mw-split` / `#mw-logout-wrap`) use `position: fixed` with `z-index: 9999` to fully override Keycloak's default PatternFly shell, ensuring the custom layout fills the viewport correctly regardless of the surrounding Keycloak page structure.
- A small inline script in `login.ftl` moves `#mw-split` directly onto `<body>` after DOM load for the same reason.
- No external CSS frameworks or JS libraries are required.
- The theme extends `keycloak` as its parent via `theme.properties`, so all other pages (error, register, OTP, etc.) fall back to the default Keycloak styles automatically without any extra work.
=======
# 🚀 Plug Auth Client (Frontend)

This is the frontend application for the Plug Auth system.

Built using: - ⚛️ React - ⚡ Vite - 🔐 Keycloak (via FastAPI backend) -
🌐 REST API integration

------------------------------------------------------------------------

# 📌 Project Overview

This frontend application:

-   Displays Landing Page
-   Redirects user to Keycloak login
-   Receives authentication via backend session
-   Fetches authenticated user details from backend
-   Displays role-based dashboard

Authentication is handled by the backend (FastAPI). The frontend only
consumes secured endpoints.

------------------------------------------------------------------------

# 🏗️ Architecture

React (5173)\
↓\
FastAPI Backend (8000)\
↓\
Keycloak (8080)

Login Flow:

1.  User clicks "Get Started"
2.  Redirect to backend `/login`
3.  Keycloak authentication
4.  Backend stores session
5.  Redirect to `/dashboard`
6.  Frontend calls `/me`
7.  Dashboard displays user info

------------------------------------------------------------------------

# 🛠️ Tech Stack

-   React 18+
-   Vite
-   JavaScript (ES6+)
-   CSS
-   Fetch API
-   React Router

------------------------------------------------------------------------

# 📂 Project Structure

    src/
    │
    ├── pages/
    │   ├── LandingPage.jsx
    │   ├── Dashboard.jsx
    │
    ├── api/
    │   └── auth.js
    │
    ├── App.jsx
    ├── main.jsx
    └── index.css

------------------------------------------------------------------------

# ⚙️ Environment Setup

Create a `.env` file in the root:

    VITE_API_BASE_URL=http://localhost:8000

If using production backend:

    VITE_API_BASE_URL=https://your-api-domain.com

------------------------------------------------------------------------

# 📦 Installation

Clone the repository:

    git clone https://github.com/<org>/<repo>.git
    cd <repo>

Install dependencies:

    npm install

------------------------------------------------------------------------

# ▶️ Running the App

Start development server:

    npm run dev

App runs at:

    http://localhost:5173

------------------------------------------------------------------------

# 🔐 Authentication

Authentication is session-based.

Frontend does NOT store JWT tokens.

The backend:

-   Handles OAuth2 flow
-   Stores session cookie
-   Returns user data via `/me`

Frontend fetch example:

    fetch("http://localhost:8000/me", {
      credentials: "include"
    })

------------------------------------------------------------------------

# 📡 API Endpoints Used

  Endpoint      Purpose
  ------------- ------------------------
  `/login`      Redirect to Keycloak
  `/callback`   OAuth callback
  `/logout`     Logout user
  `/me`         Get authenticated user
  `/health`     Health check

------------------------------------------------------------------------

# 🧪 Debugging

To view user data in browser console:

    fetch("http://localhost:8000/me", {
      credentials: "include"
    })
    .then(res => res.json())
    .then(console.log)

------------------------------------------------------------------------

# 🌳 Git Workflow

We follow this branch structure:

    main        → Production
    develop     → Integration
    feature/*   → Features
    hotfix/*    → Production fixes

Creating a feature branch:

    git checkout develop
    git pull origin develop
    git checkout -b feature/branch-name

------------------------------------------------------------------------

# 🚀 Deployment

Build production bundle:

    npm run build

Output folder:

    dist/

Deploy this folder to:

-   Nginx
-   Vercel
-   Netlify
-   Docker
-   Any static hosting service

------------------------------------------------------------------------

# ⚠️ Important Notes

-   Do NOT commit `.env`
-   Do NOT store tokens in localStorage
-   Always use `credentials: "include"` for session-based requests
-   Backend must allow CORS for frontend origin

------------------------------------------------------------------------

# 👨‍💻 Contributors

Frontend Team\
Backend Team

------------------------------------------------------------------------

# 📄 License

Internal Project -- HDFC Internship
>>>>>>> 6a6fb501262a7ffc493b97492d89e25e281ed7de
