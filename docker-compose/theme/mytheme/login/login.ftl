<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username','password') displayInfo=realm.password && realm.registrationAllowed && !registrationDisabled??; section>
    <#if section = "header">
        ${msg("loginAccountTitle")}
    <#elseif section = "form">
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700;800&display=swap');

            /* ── Reset & base ── */
            *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

            html { height: 100%; }

            body, body.login-pf {
                font-family: 'Poppins', sans-serif !important;
                background: #f0f2f5 !important;
                min-height: 100vh;
                height: 100%;
            }

            /* ── Hide ALL default Keycloak structural chrome ── */
            #kc-header,
            #kc-header-wrapper,
            .login-pf-header,
            #kc-page-title,
            .pf-v5-c-page,
            .pf-v5-c-page__header,
            .pf-v5-c-login__header,
            .pf-v5-c-login__main-header,
            .pf-v5-c-login__footer,
            .pf-v5-c-login__main-footer,
            header.pf-v5-c-page__header { display: none !important; }

            /* ── Override the Keycloak login page shell ── */
            .pf-v5-c-login,
            .login-pf-page {
                background: #f0f2f5 !important;
                display: block !important;
                min-height: 100vh;
            }

            /* Make the main login card full-width / unstyled */
            .pf-v5-c-login__main,
            .pf-v5-c-card,
            .pf-v5-c-login__main-body,
            .card-pf {
                background: transparent !important;
                box-shadow: none !important;
                border: none !important;
                border-radius: 0 !important;
                padding: 0 !important;
                margin: 0 !important;
                max-width: none !important;
                width: 100% !important;
            }

            /* ── CENTRED WRAPPER ── */
            body, body.login-pf {
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
            }

            #mw-split {
                display: flex;
                align-items: center;
                justify-content: center;
                width: 100vw;
                min-height: 100vh;
                max-width: none;
                padding: 3rem 4rem;
                gap: 5rem;
                position: fixed;
                top: 0;
                left: 0;
                background: #f0f2f5;
                z-index: 9999;
            }

            /* ── LEFT: lock illustration ── */
            #mw-illustration {
                flex: 1;
                display: flex;
                align-items: center;
                justify-content: center;
                min-width: 0;
                max-width: 420px;
            }

            #mw-illustration svg {
                width: 100%;
                max-width: 380px;
                height: auto;
            }

            /* ── Form area ── */
            #mw-form-area {
                flex: 1;
                min-width: 0;
                max-width: 420px;
                background: #ffffff;
                border-radius: 20px;
                padding: 2.8rem 2.5rem;
                box-shadow: 0 8px 40px rgba(80, 70, 229, 0.10);
                text-align: center;
            }

            .mw-welcome {
                font-size: 1.05rem;
                font-weight: 400;
                color: #4a4a6a;
                margin-bottom: 0.1rem;
            }

            .mw-brand {
                font-size: 3rem;
                font-weight: 800;
                color: #5046e5;
                letter-spacing: -1px;
                line-height: 1.05;
                margin-bottom: 0.1rem;
            }

            .mw-tagline {
                font-size: 0.92rem;
                font-weight: 700;
                color: #5046e5;
                margin-bottom: 2.4rem;
            }

            /* ── Input fields ── */
            .mw-field {
                display: flex;
                align-items: center;
                background: #ebebef;
                border-radius: 10px;
                border: 1.5px solid transparent;
                padding: 0.65rem 1rem;
                margin-bottom: 1rem;
                transition: border-color 0.2s, background 0.2s;
                gap: 0.8rem;
                text-align: left;
            }

            .mw-field:focus-within {
                border-color: #5046e5;
                background: #fff;
            }

            .mw-field.mw-err { border-color: #ef4444; }

            .mw-field-icon {
                color: #2a2a3a;
                display: flex;
                align-items: center;
                flex-shrink: 0;
            }
            .mw-field-icon svg { width: 20px; height: 20px; }

            .mw-field-inner {
                flex: 1;
                display: flex;
                flex-direction: column;
            }

            .mw-lbl {
                font-size: 0.66rem;
                color: #888;
                font-weight: 500;
                line-height: 1;
                margin-bottom: 0.18rem;
            }

            .mw-field input {
                border: none !important;
                background: transparent !important;
                font-family: 'Poppins', sans-serif !important;
                font-size: 0.92rem !important;
                font-weight: 500 !important;
                color: #1a1a2e !important;
                outline: none !important;
                padding: 0 !important;
                box-shadow: none !important;
                width: 100%;
            }
            .mw-field input::placeholder { color: #bbb; }

            .mw-eye {
                background: none; border: none;
                cursor: pointer;
                color: #555;
                display: flex; align-items: center;
                padding: 0; flex-shrink: 0;
                transition: color 0.2s;
            }
            .mw-eye:hover { color: #5046e5; }
            .mw-eye svg { width: 18px; height: 18px; }

            .mw-err-txt {
                font-size: 0.72rem;
                color: #ef4444;
                margin: -0.5rem 0 0.75rem 0.25rem;
                text-align: left;
            }

            /* ── Options row ── */
            .mw-opts {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 1.75rem;
                font-size: 0.78rem;
                text-align: left;
            }
            .mw-chk {
                display: flex; align-items: center; gap: 0.4rem;
                color: #666; cursor: pointer; font-weight: 500;
            }
            .mw-chk input[type="checkbox"] { accent-color: #5046e5; width: 14px; height: 14px; }
            .mw-fgt { color: #5046e5; text-decoration: none; font-weight: 600; }
            .mw-fgt:hover { text-decoration: underline; }

            /* ── Login button ── */
            #kc-login {
                display: block;
                width: 100%;
                background: #3b67f8 !important;
                color: #fff !important;
                border: none !important;
                border-radius: 10px !important;
                padding: 1rem !important;
                font-family: 'Poppins', sans-serif !important;
                font-size: 1rem !important;
                font-weight: 600 !important;
                cursor: pointer !important;
                box-shadow: 0 6px 22px rgba(59,103,248,0.35) !important;
                transition: background 0.2s, box-shadow 0.2s, transform 0.1s !important;
            }
            #kc-login:hover {
                background: #2952e8 !important;
                box-shadow: 0 8px 28px rgba(59,103,248,0.45) !important;
                transform: translateY(-1px);
            }
            #kc-login:active { transform: translateY(0); }
            #kc-login:disabled { opacity: 0.6; }

            /* ── Register link ── */
            #kc-registration-container {
                text-align: center;
                margin-top: 1.25rem;
                font-size: 0.82rem;
                color: #888;
            }
            #kc-registration-container a { color: #5046e5; font-weight: 600; text-decoration: none; }
            #kc-registration-container a:hover { text-decoration: underline; }

            /* ── Social providers ── */
            #kc-social-providers { margin-top: 1.25rem; }
            #kc-social-providers ul { list-style: none; display: flex; gap: 0.6rem; justify-content: center; }
            #kc-social-providers li a {
                display: flex; align-items: center; justify-content: center;
                width: 44px; height: 44px;
                border-radius: 10px;
                background: #ebebef;
                border: 1.5px solid #ddd;
                text-decoration: none;
                transition: border-color 0.2s, background 0.2s;
            }
            #kc-social-providers li a:hover { border-color: #5046e5; background: #eef; }
            #kc-social-providers li a svg { width: 18px; height: 18px; fill: #444; }

            /* ── Alert ── */
            .pf-v5-c-alert, .alert-error {
                background: #fff1f1 !important;
                border: 1px solid #fca5a5 !important;
                border-radius: 8px !important;
                color: #dc2626 !important;
                font-size: 0.8rem !important;
                font-family: 'Poppins', sans-serif !important;
                padding: 0.7rem 1rem !important;
                margin-bottom: 1rem;
                text-align: left;
            }

            #id-hidden-input { display: none; }

            /* ── Responsive ── */
            @media (max-width: 768px) {
                #mw-illustration { display: none; }
                #mw-split { padding: 2rem 1.5rem; gap: 0; max-width: 480px; }
                #mw-form-area { max-width: 100%; flex: none; width: 100%; }
            }
            @media (max-width: 480px) {
                #mw-split { padding: 1.5rem 1rem; }
                #mw-form-area { padding: 2rem 1.4rem; border-radius: 14px; }
                .mw-brand { font-size: 2.2rem; }
            }
        </style>

        <div id="mw-split">

            <!-- LEFT: Brand lock illustration -->
            <div id="mw-illustration">
                <svg viewBox="0 0 380 420" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                        <radialGradient id="bgBlob" cx="50%" cy="50%" r="50%">
                            <stop offset="0%" stop-color="#ede9fe"/>
                            <stop offset="100%" stop-color="#ddd6fe" stop-opacity="0.4"/>
                        </radialGradient>
                        <linearGradient id="bodyGrad" x1="80" y1="190" x2="300" y2="400" gradientUnits="userSpaceOnUse">
                            <stop offset="0%" stop-color="#6d58f0"/>
                            <stop offset="100%" stop-color="#3b67f8"/>
                        </linearGradient>
                        <linearGradient id="shackleGrad" x1="140" y1="60" x2="240" y2="185" gradientUnits="userSpaceOnUse">
                            <stop offset="0%" stop-color="#7c6ff7"/>
                            <stop offset="100%" stop-color="#5046e5"/>
                        </linearGradient>
                        <linearGradient id="keyHoleGrad" x1="176" y1="250" x2="204" y2="330" gradientUnits="userSpaceOnUse">
                            <stop offset="0%" stop-color="#c4b9ff"/>
                            <stop offset="100%" stop-color="#a78bfa"/>
                        </linearGradient>
                        <filter id="shadow" x="-20%" y="-10%" width="140%" height="130%">
                            <feDropShadow dx="0" dy="12" stdDeviation="22" flood-color="#5046e5" flood-opacity="0.22"/>
                        </filter>
                        <filter id="softShadow" x="-10%" y="-5%" width="120%" height="120%">
                            <feDropShadow dx="0" dy="4" stdDeviation="8" flood-color="#5046e5" flood-opacity="0.15"/>
                        </filter>
                    </defs>

                    <!-- Background blob -->
                    <ellipse cx="190" cy="220" rx="175" ry="185" fill="url(#bgBlob)"/>

                    <!-- Decorative rings -->
                    <circle cx="190" cy="220" r="158" stroke="#c4b9ff" stroke-width="1.5" stroke-dasharray="6 8" opacity="0.55"/>
                    <circle cx="190" cy="220" r="135" stroke="#ddd6fe" stroke-width="1" opacity="0.6"/>

                    <!-- Floating sparkles -->
                    <circle cx="52"  cy="110" r="5" fill="#7c6ff7" opacity="0.5"/>
                    <circle cx="68"  cy="94"  r="3" fill="#3b67f8" opacity="0.4"/>
                    <circle cx="318" cy="130" r="4" fill="#5046e5" opacity="0.45"/>
                    <circle cx="336" cy="116" r="2.5" fill="#7c6ff7" opacity="0.4"/>
                    <circle cx="44"  cy="310" r="3.5" fill="#3b67f8" opacity="0.35"/>
                    <circle cx="330" cy="320" r="4"   fill="#5046e5" opacity="0.4"/>

                    <!-- Small star accents -->
                    <path d="M58 165 l3 8 l3-8 l-6 4.5 l6 4.5z" fill="#7c6ff7" opacity="0.5"/>
                    <path d="M316 175 l3 8 l3-8 l-6 4.5 l6 4.5z" fill="#3b67f8" opacity="0.45"/>

                    <!-- Lock shackle (U-bar) -->
                    <path d="M138 185 L138 130 Q138 65 190 65 Q242 65 242 130 L242 185"
                          stroke="url(#shackleGrad)" stroke-width="28" stroke-linecap="round"
                          fill="none" filter="url(#softShadow)"/>
                    <!-- Shackle inner highlight -->
                    <path d="M144 185 L144 132 Q144 78 190 78 Q236 78 236 132 L236 185"
                          stroke="#a78bfa" stroke-width="10" stroke-linecap="round"
                          fill="none" opacity="0.4"/>

                    <!-- Lock body -->
                    <rect x="82" y="180" width="216" height="186" rx="28" fill="url(#bodyGrad)" filter="url(#shadow)"/>

                    <!-- Body top sheen -->
                    <rect x="82" y="180" width="216" height="52" rx="28" fill="white" opacity="0.08"/>

                    <!-- Horizontal ridges on body -->
                    <line x1="106" y1="232" x2="274" y2="232" stroke="white" stroke-width="1" opacity="0.1"/>
                    <line x1="106" y1="248" x2="274" y2="248" stroke="white" stroke-width="1" opacity="0.07"/>

                    <!-- Keyhole circle -->
                    <circle cx="190" cy="288" r="30" fill="url(#keyHoleGrad)" filter="url(#softShadow)"/>
                    <circle cx="190" cy="288" r="30" stroke="white" stroke-width="1.5" opacity="0.2"/>

                    <!-- Keyhole inner dark -->
                    <circle cx="190" cy="286" r="12" fill="#2d1b8e" opacity="0.55"/>
                    <rect x="186" y="295" width="8" height="22" rx="4" fill="#2d1b8e" opacity="0.5"/>

                    <!-- Dot accents on body -->
                    <circle cx="120" cy="335" r="4" fill="white" opacity="0.15"/>
                    <circle cx="260" cy="335" r="4" fill="white" opacity="0.15"/>

                    <!-- Bottom text label -->
                    <rect x="135" y="384" width="110" height="28" rx="14" fill="#5046e5" opacity="0.15"/>
                    <text x="190" y="402" text-anchor="middle" font-family="Poppins, sans-serif"
                          font-size="11" font-weight="700" fill="#5046e5" letter-spacing="2" opacity="0.8">SECURE</text>
                </svg>
            </div>

            <!-- Form card -->
            <div id="mw-form-area">
                <p class="mw-welcome">Welcome to</p>
                <h1 class="mw-brand">Mywallet</h1>
                <p class="mw-tagline">A personal wallet</p>

                <#if realm.password>
                    <form id="kc-form-login" action="${url.loginAction}" method="post"
                          onsubmit="document.getElementById('kc-login').disabled = true; return true;">

                        <!-- Email / Username -->
                        <#if !usernameHidden??>
                            <div class="mw-field <#if messagesPerField.existsError('username','password')>mw-err</#if>">
                                <span class="mw-field-icon">
                                    <svg viewBox="0 0 24 24" fill="currentColor">
                                        <path d="M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z"/>
                                    </svg>
                                </span>
                                <div class="mw-field-inner">
                                    <span class="mw-lbl"><#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>Email</#if></span>
                                    <input tabindex="1" id="username" name="username"
                                           value="${(login.username!'')}"
                                           type="text" autofocus autocomplete="off"
                                           placeholder="example@gmail.com"
                                           aria-invalid="<#if messagesPerField.existsError('username','password')>true</#if>"/>
                                </div>
                            </div>
                            <#if messagesPerField.existsError('username','password')>
                                <p class="mw-err-txt">${kcSanitize(messagesPerField.getFirstError('username','password'))?no_esc}</p>
                            </#if>
                        </#if>

                        <!-- Password -->
                        <div class="mw-field <#if usernameHidden?? && messagesPerField.existsError('username','password')>mw-err</#if>">
                            <span class="mw-field-icon">
                                <svg viewBox="0 0 24 24" fill="currentColor">
                                    <path d="M12.65 10A5.99 5.99 0 0 0 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6a5.99 5.99 0 0 0 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/>
                                </svg>
                            </span>
                            <div class="mw-field-inner">
                                <span class="mw-lbl">Password</span>
                                <input tabindex="2" id="password" name="password"
                                       type="password" autocomplete="off"
                                       placeholder="••••••••••••"
                                       aria-invalid="<#if messagesPerField.existsError('username','password')>true</#if>"/>
                            </div>
                            <button class="mw-eye" type="button"
                                    aria-label="${msg('showPassword')}"
                                    aria-controls="password"
                                    data-password-toggle
                                    data-icon-show="${properties.kcFormPasswordVisibilityIconShow!}"
                                    data-icon-hide="${properties.kcFormPasswordVisibilityIconHide!}"
                                    data-label-show="${msg('showPassword')}"
                                    data-label-hide="${msg('hidePassword')}">
                                <svg viewBox="0 0 24 24" fill="currentColor">
                                    <path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/>
                                </svg>
                            </button>
                        </div>
                        <#if usernameHidden?? && messagesPerField.existsError('username','password')>
                            <p class="mw-err-txt">${kcSanitize(messagesPerField.getFirstError('username','password'))?no_esc}</p>
                        </#if>

                        <!-- Remember + Forgot -->
                        <div class="mw-opts">
                            <#if realm.rememberMe && !usernameHidden??>
                                <label class="mw-chk">
                                    <input tabindex="3" id="rememberMe" name="rememberMe" type="checkbox"
                                           <#if login.rememberMe??>checked</#if>>
                                    ${msg("rememberMe")}
                                </label>
                            <#else>
                                <span></span>
                            </#if>
                            <#if realm.resetPasswordAllowed>
                                <a class="mw-fgt" tabindex="5" href="${url.loginResetCredentialsUrl}">${msg("doForgotPassword")}</a>
                            </#if>
                        </div>

                        <input type="hidden" id="id-hidden-input" name="credentialId"
                               <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>/>

                        <input tabindex="4" id="kc-login" name="login" type="submit" value="Login"/>
                    </form>
                </#if>
            </div>
        </div>

        <script type="module" src="${url.resourcesPath}/js/passwordVisibility.js"></script>

        <script>
            (function() {
                var split = document.getElementById('mw-split');
                if (split && document.body) {
                    document.body.appendChild(split);
                }
            })();
        </script>

    <#elseif section = "info">
        <#if realm.password && realm.registrationAllowed && !registrationDisabled??>
            <div id="kc-registration-container">
                <span>${msg("noAccount")} <a tabindex="6" href="${url.registrationUrl}">${msg("doRegister")}</a></span>
            </div>
        </#if>

    <#elseif section = "socialProviders">
        <#if realm.password && social.providers??>
            <div id="kc-social-providers">
                <ul>
                    <#list social.providers as p>
                        <li>
                            <a id="social-${p.alias}" aria-label="${p.displayName}" type="button" href="${p.loginUrl}">
                                <#if p.iconClasses?has_content>
                                    <#switch p.alias>
                                        <#case "google">
                                            <svg viewBox="0 0 488 512"><path d="M488 261.8C488 403.3 391.1 504 248 504 110.8 504 0 393.2 0 256S110.8 8 248 8c66.8 0 123 24.5 166.3 64.9l-67.5 64.9C258.5 52.6 94.3 116.6 94.3 256c0 86.5 69.1 156.6 153.7 156.6 98.2 0 135-70.4 140.8-106.9H248v-85.3h236.1c2.3 12.7 3.9 24.9 3.9 41.4z"/></svg>
                                            <#break>
                                        <#case "github">
                                            <svg viewBox="0 0 496 512"><path d="M244.8 8C106.1 8 0 113.3 0 252c0 110.9 69.8 205.8 169.5 239.2 12.8 2.3 17.3-5.6 17.3-12.1 0-6.2-.3-40.4-.3-61.4 0 0-70 15-84.7-29.8 0 0-11.4-29.1-27.8-36.6 0 0-22.9-15.7 1.6-15.4 0 0 24.9 2 38.6 25.8 21.9 38.6 58.6 27.5 72.9 20.9 2.3-16 8.8-27.1 16-33.7-55.9-6.2-112.3-14.3-112.3-110.5 0-27.5 7.6-41.3 23.6-58.9-2.6-6.5-11.1-33.3 2.6-67.9 20.9-6.5 69 27 69 27 20-5.6 41.5-8.5 62.8-8.5s42.8 2.9 62.8 8.5c0 0 48.1-33.6 69-27 13.7 34.7 5.2 61.4 2.6 67.9 16 17.7 25.8 31.5 25.8 58.9 0 96.5-58.9 104.2-114.8 110.5 9.2 7.9 17 22.9 17 46.4 0 33.7-.3 75.4-.3 83.6 0 6.5 4.6 14.4 17.3 12.1C428.2 457.8 496 362.9 496 252 496 113.3 383.5 8 244.8 8z"/></svg>
                                            <#break>
                                        <#default>
                                            <span style="font-size:0.65rem;color:#555;font-weight:600">${p.displayName!}</span>
                                    </#switch>
                                <#else>
                                    <span style="font-size:0.65rem;color:#555;font-weight:600">${p.displayName!}</span>
                                </#if>
                            </a>
                        </li>
                    </#list>
                </ul>
            </div>
        </#if>
    </#if>
</@layout.registrationLayout>
