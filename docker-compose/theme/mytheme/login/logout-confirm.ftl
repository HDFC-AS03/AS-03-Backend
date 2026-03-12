<!DOCTYPE html>
<html lang="${locale!'en'}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${msg("logoutConfirmTitle")}</title>
    
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700;800&display=swap');

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        html { height: 100%; }

        body {
            font-family: 'Poppins', sans-serif !important;
            background: #f0f2f5 !important;
            min-height: 100vh;
            height: 100%;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            margin: 0;
        }

        /* ── Full viewport overlay ── */
        #mw-logout-wrap {
            position: fixed;
            top: 0; left: 0;
            width: 100vw;
            min-height: 100vh;
            background: #f0f2f5;
            z-index: 9999;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 5rem;
            padding: 3rem 4rem;
        }

        /* ── LEFT: illustration ── */
        #mw-logout-illustration {
            flex: 1;
            max-width: 420px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        #mw-logout-illustration svg {
            width: 100%;
            max-width: 360px;
            height: auto;
        }

        /* ── RIGHT: card ── */
        #mw-logout-card {
            flex: 1;
            max-width: 420px;
            background: #fff;
            border-radius: 20px;
            padding: 2.8rem 2.5rem;
            box-shadow: 0 8px 40px rgba(80, 70, 229, 0.10);
            text-align: center;
        }

        /* Icon circle */
        .mw-icon-circle {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            background: linear-gradient(135deg, #ede9fe, #ddd6fe);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 1.5rem;
        }
        .mw-icon-circle svg {
            width: 38px;
            height: 38px;
        }

        .mw-brand {
            font-size: 2rem;
            font-weight: 800;
            color: #5046e5;
            letter-spacing: -0.5px;
            line-height: 1.1;
            margin-bottom: 0.3rem;
        }

        .mw-subtitle {
            font-size: 0.88rem;
            color: #888;
            font-weight: 400;
            margin-bottom: 2rem;
        }

        .mw-divider {
            height: 1px;
            background: #f0f0f5;
            margin: 0 -2.5rem 2rem;
        }

        .mw-question {
            font-size: 1rem;
            font-weight: 600;
            color: #2a2a3a;
            margin-bottom: 0.5rem;
        }

        .mw-desc {
            font-size: 0.82rem;
            color: #aaa;
            margin-bottom: 2rem;
            font-weight: 400;
        }

        /* ── Logout button ── */
        #kc-logout {
            display: block;
            width: 100%;
            background: linear-gradient(135deg, #5046e5, #3b67f8) !important;
            color: #fff !important;
            border: none !important;
            border-radius: 10px !important;
            padding: 1rem !important;
            font-family: 'Poppins', sans-serif !important;
            font-size: 1rem !important;
            font-weight: 600 !important;
            cursor: pointer !important;
            box-shadow: 0 6px 22px rgba(80, 70, 229, 0.35) !important;
            transition: opacity 0.2s, transform 0.1s !important;
            letter-spacing: 0.3px;
        }
        #kc-logout:hover { opacity: 0.9; transform: translateY(-1px); }
        #kc-logout:active { transform: translateY(0); }

        /* ── Cancel link ── */
        .mw-cancel {
            display: block;
            margin-top: 1rem;
            font-size: 0.82rem;
            color: #888;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.2s;
        }
        .mw-cancel:hover { color: #5046e5; }

        /* ── Responsive ── */
        @media (max-width: 768px) {
            #mw-logout-illustration { display: none; }
            #mw-logout-wrap { gap: 0; padding: 2rem 1.5rem; }
            #mw-logout-card { max-width: 100%; }
        }
        @media (max-width: 480px) {
            #mw-logout-wrap { padding: 1.5rem 1rem; }
            #mw-logout-card { padding: 2rem 1.4rem; border-radius: 14px; }
        }
    </style>
</head>

<body>
    <div id="mw-logout-wrap">

        <div id="mw-logout-illustration">
            <svg viewBox="0 0 380 420" fill="none" xmlns="http://www.w3.org/2000/svg">
                <defs>
                    <radialGradient id="logoutBg" cx="50%" cy="50%" r="50%">
                        <stop offset="0%" stop-color="#ede9fe"/>
                        <stop offset="100%" stop-color="#ddd6fe" stop-opacity="0.35"/>
                    </radialGradient>
                    <linearGradient id="logoutBody" x1="80" y1="190" x2="300" y2="400" gradientUnits="userSpaceOnUse">
                        <stop offset="0%" stop-color="#7c6ff7"/>
                        <stop offset="100%" stop-color="#3b67f8"/>
                    </linearGradient>
                    <linearGradient id="shackleOpen" x1="140" y1="40" x2="300" y2="130" gradientUnits="userSpaceOnUse">
                        <stop offset="0%" stop-color="#a78bfa"/>
                        <stop offset="100%" stop-color="#5046e5"/>
                    </linearGradient>
                    <linearGradient id="logoutKH" x1="176" y1="250" x2="204" y2="330" gradientUnits="userSpaceOnUse">
                        <stop offset="0%" stop-color="#c4b9ff"/>
                        <stop offset="100%" stop-color="#a78bfa"/>
                    </linearGradient>
                    <filter id="lShadow" x="-20%" y="-10%" width="140%" height="130%">
                        <feDropShadow dx="0" dy="10" stdDeviation="20" flood-color="#5046e5" flood-opacity="0.2"/>
                    </filter>
                    <filter id="lSoft" x="-10%" y="-5%" width="120%" height="120%">
                        <feDropShadow dx="0" dy="4" stdDeviation="8" flood-color="#5046e5" flood-opacity="0.15"/>
                    </filter>
                </defs>

                <ellipse cx="190" cy="225" rx="170" ry="180" fill="url(#logoutBg)"/>

                <circle cx="190" cy="225" r="155" stroke="#c4b9ff" stroke-width="1.5" stroke-dasharray="6 8" opacity="0.5"/>

                <circle cx="50"  cy="115" r="5"   fill="#7c6ff7" opacity="0.45"/>
                <circle cx="66"  cy="98"  r="3"   fill="#3b67f8" opacity="0.35"/>
                <circle cx="316" cy="135" r="4"   fill="#5046e5" opacity="0.4"/>
                <circle cx="334" cy="118" r="2.5" fill="#7c6ff7" opacity="0.35"/>
                <circle cx="42"  cy="315" r="3.5" fill="#3b67f8" opacity="0.3"/>
                <circle cx="328" cy="325" r="4"   fill="#5046e5" opacity="0.35"/>
                <path d="M56 168 l3 8 l3-8 l-6 4.5 l6 4.5z"  fill="#7c6ff7" opacity="0.45"/>
                <path d="M314 178 l3 8 l3-8 l-6 4.5 l6 4.5z" fill="#3b67f8" opacity="0.4"/>

                <path d="M232 185 L232 130 Q232 72 190 72"
                      stroke="url(#shackleOpen)" stroke-width="26" stroke-linecap="round" fill="none" filter="url(#lSoft)"/>
                <path d="M148 185 L148 185 Q148 160 178 110 Q200 72 248 58"
                      stroke="url(#shackleOpen)" stroke-width="26" stroke-linecap="round" fill="none" filter="url(#lSoft)"/>
                <circle cx="248" cy="58" r="13" fill="#a78bfa" opacity="0.7"/>

                <path d="M238 185 L238 132 Q238 82 190 82"
                      stroke="#c4b9ff" stroke-width="8" stroke-linecap="round" fill="none" opacity="0.35"/>

                <rect x="84" y="183" width="212" height="182" rx="26" fill="url(#logoutBody)" filter="url(#lShadow)"/>

                <rect x="84" y="183" width="212" height="50" rx="26" fill="white" opacity="0.08"/>

                <line x1="108" y1="234" x2="272" y2="234" stroke="white" stroke-width="1" opacity="0.1"/>
                <line x1="108" y1="250" x2="272" y2="250" stroke="white" stroke-width="1" opacity="0.07"/>

                <circle cx="190" cy="286" r="29" fill="url(#logoutKH)" filter="url(#lSoft)"/>
                <circle cx="190" cy="286" r="29" stroke="white" stroke-width="1.5" opacity="0.2"/>
                <circle cx="190" cy="284" r="11" fill="#2d1b8e" opacity="0.5"/>
                <rect x="186" y="293" width="8" height="21" rx="4" fill="#2d1b8e" opacity="0.45"/>

                <circle cx="118" cy="332" r="4" fill="white" opacity="0.14"/>
                <circle cx="262" cy="332" r="4" fill="white" opacity="0.14"/>

                <rect x="138" y="385" width="104" height="26" rx="13" fill="#5046e5" opacity="0.14"/>
                <text x="190" y="402" text-anchor="middle" font-family="Poppins, sans-serif"
                      font-size="10" font-weight="700" fill="#5046e5" letter-spacing="3" opacity="0.75">SEE YOU</text>
            </svg>
        </div>

        <div id="mw-logout-card">

            <div class="mw-icon-circle">
                <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" stroke="#5046e5" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
                    <polyline points="16 17 21 12 16 7" stroke="#3b67f8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
                    <line x1="21" y1="12" x2="9" y2="12" stroke="#3b67f8" stroke-width="2.2" stroke-linecap="round"/>
                </svg>
            </div>

            <h1 class="mw-brand">Mywallet</h1>
            <p class="mw-subtitle">A personal wallet</p>

            <div class="mw-divider"></div>

            <p class="mw-question">Logging out?</p>
            <p class="mw-desc">You'll need to sign in again to access your wallet.</p>

            <form class="form-actions" action="${url.logoutConfirmAction}" method="POST">
                <input type="hidden" name="session_code" value="${logoutConfirm.code}">
                <input id="kc-logout" name="confirmLogout" type="submit" value="${msg("doLogout")}"/>
            </form>

            <#if logoutConfirm.skipLink>
            <#else>
                <#if (client.baseUrl)?has_content>
                    <a class="mw-cancel" href="${client.baseUrl}">← Back to application</a>
                </#if>
            </#if>
        </div>
    </div>
</body>
</html>