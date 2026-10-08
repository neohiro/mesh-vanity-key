---
layout: default
title: neohiro
description: "Security hardening & privacy tools for Windows and Linux. Defense is the best defense."
---

<div class="hero" id="home">
  <canvas id="matrix-canvas" aria-hidden="true"></canvas>
  <div class="container">
    <div class="hero-content">
      <img class="hero-avatar"
           src="https://github.com/neohiro.png"
           alt="neohiro avatar"
           width="92" height="92"
           fetchpriority="high">
      <div class="hero-badges" aria-label="Affiliations">
        <span class="badge badge-metapod">METAPOD</span>
        <span class="badge badge-fpm">FrenzyPenguin Media</span>
      </div>

      <h1 class="hero-title">Defense is the best defense.</h1>

      <p class="hero-tagline">
        Open-source security hardening for Windows &amp; Linux.
        Exploit mitigation that actually works. Zero telemetry. Ever.
      </p>

      <div class="hero-cta">
        <a href="#featured-tools" class="btn btn-primary">Explore Tools</a>
        <a href="{{ '/repositories/' | relative_url }}" class="btn btn-secondary">All Repositories</a>
        <a href="https://github.com/login/oauth/authorize?client_id=neohiro&scope=read%3Auser" class="btn btn-ghost btn-login" id="login-btn">
          <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18" aria-hidden="true"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>
          Login with GitHub
        </a>
      </div>
    </div>
  </div>
</div>

<!-- Live Quote Typewriter -->
<section class="section section-quotes" id="quotes">
  <div class="typewriter-wrap" aria-live="polite">
    <span class="typewriter-prefix" aria-hidden="true">✦ live signal</span>
    <div class="typewriter" id="tw-text" aria-atomic="true"></div>
    <div class="typewriter-attribution" id="tw-attrib"></div>
  </div>
</section>

<script>
  (function () {
    const QUOTES = [
      { t: "Defense is the best defense.",            a: "neohiro" },
      { t: "One command. Zero compromise.",           a: "Harden-Windows" },
      { t: "Your system. Your rules. Our tooling.",   a: "FrenzyPenguin Media" },
      { t: "Encrypted DNS for everyone.",             a: "dnscrypt-proxy-gui" },
      { t: "Ship the hardening. Skip the telemetry.", a: "neohiro" },
      { t: "Auditd, AppArmor, Tor — automated.",      a: "neohiro/linux" },
      { t: "Block the noise. Trust the packet.",      a: "Cripple-NetStrip" },
      { t: "ASR · CFG · DEP · SEHOP. Toggled.",       a: "ExploitProtection" },
      { t: "Privacy isn't a feature. It's the floor.", a: "FrenzyPenguin Media" },
      { t: "Make the boring right. Then ship.",       a: "neohiro" },
      { t: "Honeypots, with zero config.",            a: "HoneyScan" },
      { t: "STIG-grade. In one command.",             a: "Harden-Windows" },
      { t: "No accounts. No compromises.",            a: "neohiro" },
      { t: "Encrypted DNS, but make it graphical.",   a: "dnscrypt-proxy-gui" },
      { t: "A firewall you actually understand.",     a: "Cripple-NetStrip" },
      { t: "MITRE mapped. ASR enabled. SEHOP on.",    a: "ExploitProtection" },
      { t: "All your repos, in one searchable index.", a: "neohiro/repositories" },
      { t: "Three heartbeats. One body.",             a: "neohiro/heartbeats" },
      { t: "Production tools, not demos.",            a: "neohiro" },
      { t: "Made by humans, for sysadmins.",          a: "FrenzyPenguin Media" },
      { t: "Zero fluff. Lots of evidence.",           a: "neohiro" },
      { t: "If it can break, we audit it.",           a: "neohiro-doctor" },
      { t: "Privacy is the foundation.",              a: "FrenzyPenguin Media" },
      { t: "Talk to the assistant below. It's live.", a: "neohiro AI" }
    ];

    const elText  = document.getElementById('tw-text');
    const elAttr  = document.getElementById('tw-attrib');
    if (!elText) return;

    const cursor = document.createElement('span');
    cursor.className = 'typewriter-cursor';
    elText.parentNode.insertBefore(cursor, elText.nextSibling);

    let qi = 0, ci = 0, deleting = false;

    function tick() {
      const q = QUOTES[qi];
      if (!deleting) {
        ci++;
        elText.textContent = q.t.slice(0, ci);
        elText.appendChild(cursor);
        if (ci >= q.t.length) {
          elAttr.innerHTML = '— <b>' + q.a + '</b>';
          deleting = true;
          return setTimeout(tick, 1100);
        }
        return setTimeout(tick, 28 + Math.random() * 32);
      } else {
        ci--;
        elText.textContent = q.t.slice(0, ci);
        elText.appendChild(cursor);
        if (ci <= 0) {
          deleting = false;
          qi = (qi + 1) % QUOTES.length;
          elAttr.innerHTML = '';
          return setTimeout(tick, 220);
        }
        return setTimeout(tick, 12 + Math.random() * 14);
      }
    }
    setTimeout(tick, 350);
  })();
</script>

<!-- Production-Grade Tools -->
<section class="section" id="featured-tools">
  <div class="container">
    <header class="section-header">
      <h2>Featured Tools</h2>
      <p class="section-subtitle">Production-grade security tooling for Windows and Linux — battle-tested, zero telemetry</p>
    </header>

    <div class="tools-grid">
      {% assign featured = site.data.repos.repos | where_exp: "tool", "tool.featured == true" | sort: "weight" %}
      {% for tool in featured %}
        <article class="tool-card card-3d" itemscope itemtype="https://schema.org/SoftwareApplication">
          <div class="tool-icon" aria-hidden="true">
            {% if tool.icon %}
              {{ tool.icon }}
            {% else %}
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                <rect x="3" y="3" width="18" height="18" rx="3"/>
                <path d="M9 12h6M12 9v6"/>
              </svg>
            {% endif %}
          </div>
          <h3 class="tool-name" itemprop="name">{{ tool.title }}</h3>
          <p class="tool-desc" itemprop="description">{{ tool.tagline }}</p>
          <div class="tool-meta">
            <span class="tool-platform" itemprop="operatingSystem">{{ tool.platform }}</span>
            {% if tool.language %}
              <span class="tool-lang">{{ tool.language }}</span>
            {% endif %}
          </div>
          <div class="tool-links">
            <a href="{{ tool.repo_url }}" class="tool-link" target="_blank" rel="noopener" itemprop="url">
              <svg viewBox="0 0 24 24" fill="currentColor" width="16" height="16" aria-hidden="true"><path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/></svg>
              Repository
            </a>
            {% if tool.demo_url %}
              <a href="{{ tool.demo_url }}" class="tool-link tool-link-secondary" target="_blank" rel="noopener">Demo</a>
            {% endif %}
          </div>
        </article>
      {% endfor %}
    </div>
  </div>
</section>

<!-- Hardening Guides (OS-level) -->
<section class="section section-alt" id="hardening-guides">
  <div class="container">
    <header class="section-header">
      <h2>Hardening Guides</h2>
      <p class="section-subtitle">Step-by-step post-install security for your operating system</p>
    </header>

    <div class="guides-grid">
      <article class="guide-card">
        <div class="guide-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <rect x="2" y="4" width="20" height="16" rx="2"/>
            <path d="M8 4v16M16 4v16M4 8h16"/>
          </svg>
        </div>
        <h3>Windows 10/11 STIG-Style Hardening</h3>
        <p>18 modules, 4 profiles, allow-lists, rollback, dry-run — one command.</p>
        <a href="https://github.com/neohiro/windows" class="guide-link" target="_blank" rel="noopener">
          View Guide <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
        </a>
      </article>

      <article class="guide-card">
        <div class="guide-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M12 2l10 7v10l-10 7-10-7v-10l10-7z"/>
            <path d="M2 12h20M12 2v20"/>
          </svg>
        </div>
        <h3>Linux Post-Install Hardening</h3>
        <p>Firewall, encrypted DNS, Tor, auditd, AppArmor — automated.</p>
        <a href="https://github.com/neohiro/ubuntu" class="guide-link" target="_blank" rel="noopener">
          View Guide <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
        </a>
      </article>
    </div>
  </div>
</section>

<section class="section" id="community">
  <div class="container">
    <header class="section-header">
      <h2>Community &amp; Support</h2>
      <p class="section-subtitle">Pick a project, then choose how to engage</p>
    </header>

    <div class="community-grid">
      <article class="community-card card-3d" data-href="https://github.com/neohiro?tab=repositories">
        <h3>Bug Reports</h3>
        <p>Structured issue templates on each repository with required diagnostics.</p>
        <span class="card-action">Select a project →</span>
      </article>

      <article class="community-card card-3d" data-href="https://github.com/neohiro?tab=repositories">
        <h3>Security Vulnerabilities</h3>
        <p>Private disclosure via Security Advisories tab on each repository.</p>
        <span class="card-action">Select a project →</span>
      </article>

      <article class="community-card card-3d" data-href="https://github.com/neohiro?tab=repositories">
        <h3>Discussions</h3>
        <p>Questions, showcases, and feature requests in each repo's Discussions.</p>
        <span class="card-action">Select a project →</span>
      </article>

      <article class="community-card card-3d" data-href="https://github.com/sponsors/neohiro">
        <h3>Sponsor</h3>
        <p>Support ongoing development via GitHub Sponsors or Patreon.</p>
        <span class="card-action">Sponsor neohiro →</span>
      </article>
    </div>

    <a class="fpm-spotlight card-3d" href="https://frenzypenguin-media.github.io/" target="_blank" rel="noopener" aria-label="FrenzyPenguin Media — video deep-dives on security hardening">
      <div class="community-card-icon" aria-hidden="true" style="margin: 0 auto 14px; color: var(--purple);">
        <svg viewBox="0 0 24 24" fill="currentColor" width="36" height="36"><path d="M19.615 3.184c-3.604-.246-11.631-.245-15.23 0-3.897.266-4.356 2.62-4.385 8.816.029 6.185.484 8.549 4.385 8.816 3.6.245 11.626.246 15.23 0 3.897-.266 4.356-2.62 4.385-8.816-.029-6.185-.484-8.549-4.385-8.816zm-10.615 12.814v-8l8 3.993-8 4.007z"/></svg>
      </div>
      <h3>🎬 FrenzyPenguin Media</h3>
      <p>Video deep-dives on security hardening, exploit mitigation, and privacy engineering. Weekly long-form content from the makers of neohiro.</p>
      <span class="card-action" style="color: var(--purple);">Watch on YouTube →</span>
    </a>
  </div>
</section>

<!-- Legal footer -->
<section class="section section-alt section-footer-legal" id="footer-legal">
  <div class="container" style="text-align:center;">
    <p class="footer-legal-links">
      <a href="{{ '/privacy/' | relative_url }}">Privacy</a> ·
      <a href="{{ '/tos/' | relative_url }}">Terms</a> ·
      <a href="{{ '/LICENSE/' | relative_url }}">License (GPL-3.0)</a> ·
      <a href="https://github.com/neohiro">GitHub</a>
    </p>
    <p class="footer-quote">
      <em>"Every body has organs. Every system has dependencies. We built this stack so nothing breaks quietly."</em>
    </p>
  </div>
</section>

{% include sponsor-cta.html %}

<script>
  (function() {
    const KEY = "neohiro.consent.v1";
    const saved = localStorage.getItem(KEY);
    const card = document.getElementById("consent-card");
    const accept = document.getElementById("consent-accept");
    const decline = document.getElementById("consent-decline");
    if (saved === "accepted") {
      card.classList.add("consent-accepted");
      card.classList.remove("consent-pending");
    } else if (saved === "declined") {
      card.classList.add("consent-declined");
      card.classList.remove("consent-pending");
    } else {
      card.classList.add("consent-pending");
    }
    if (accept) {
      accept.addEventListener("click", function() {
        localStorage.setItem(KEY, "accepted");
        card.classList.add("consent-accepted");
        card.classList.remove("consent-pending", "consent-declined");
        document.dispatchEvent(new CustomEvent("neohiro:consent", {detail: {ok: true}}));
        celebrate(card);
      });
    }
    if (decline) {
      decline.addEventListener("click", function() {
        localStorage.setItem(KEY, "declined");
        card.classList.add("consent-declined");
        card.classList.remove("consent-pending", "consent-accepted");
        document.dispatchEvent(new CustomEvent("neohiro:consent", {detail: {ok: false}}));
      });
    }

    function celebrate(el) {
      el.classList.add("celebrate");
      setTimeout(() => el.classList.remove("celebrate"), 1200);
    }

    document.addEventListener("click", function(e) {
      const target = e.target.closest(".btn, .legal-link, .guide-link, .card-action, .community-card, .tool-link, .fpm-spotlight");
      if (!target) return;
      const rect = target.getBoundingClientRect();
      const ripple = document.createElement("span");
      ripple.className = "click-ripple";
      const size = Math.max(rect.width, rect.height) * 1.4;
      ripple.style.width = ripple.style.height = size + "px";
      ripple.style.left = (e.clientX - rect.left - size / 2) + "px";
      ripple.style.top = (e.clientY - rect.top - size / 2) + "px";
      target.appendChild(ripple);
      setTimeout(() => ripple.remove(), 700);

      if (target.classList.contains("community-card")) {
        const href = target.dataset.href;
        if (href) {
          e.preventDefault();
          setTimeout(() => window.open(href, "_blank", "noopener"), 120);
        }
      }
    });

    const loginBtn = document.getElementById("login-btn");
    if (loginBtn) {
      loginBtn.addEventListener("click", function(e) {
        sessionStorage.setItem("neohiro.login.intent", "1");
        const rect = loginBtn.getBoundingClientRect();
        for (let i = 0; i < 12; i++) {
          const spark = document.createElement("span");
          spark.className = "login-spark";
          spark.style.left = (rect.left + rect.width / 2) + "px";
          spark.style.top = (rect.top + rect.height / 2) + "px";
          const angle = (Math.PI * 2 * i) / 12;
          const dist = 50 + Math.random() * 60;
          spark.style.setProperty("--dx", Math.cos(angle) * dist + "px");
          spark.style.setProperty("--dy", Math.sin(angle) * dist + "px");
          document.body.appendChild(spark);
          setTimeout(() => spark.remove(), 900);
        }
      });
    }

    const progress = document.createElement("div");
    progress.className = "scroll-progress";
    document.body.appendChild(progress);
    window.addEventListener("scroll", function() {
      const h = document.documentElement;
      const max = h.scrollHeight - h.clientHeight;
      const pct = max > 0 ? (h.scrollTop / max) * 100 : 0;
      progress.style.width = pct + "%";
    }, {passive: true});

    const revealTargets = document.querySelectorAll(".section, .legal-card, .tool-card, .guide-card, .community-card, .quote-card, .fpm-spotlight");
    revealTargets.forEach(el => el.classList.add("reveal"));
    if ("IntersectionObserver" in window) {
      const io = new IntersectionObserver(entries => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            entry.target.classList.add("reveal-in");
            io.unobserve(entry.target);
          }
        });
      }, {threshold: 0.08, rootMargin: "0px 0px -10% 0px"});
      revealTargets.forEach(el => io.observe(el));
    } else {
      revealTargets.forEach(el => el.classList.add("reveal-in"));
    }

    document.querySelectorAll(".tool-card, .guide-card, .quote-card, .fpm-spotlight").forEach(card => {
      card.addEventListener("mousemove", function(e) {
        const rect = card.getBoundingClientRect();
        const x = (e.clientX - rect.left) / rect.width - 0.5;
        const y = (e.clientY - rect.top) / rect.height - 0.5;
        card.style.setProperty("--mx", (x * 8) + "px");
        card.style.setProperty("--my", (y * 8) + "px");
      });
      card.addEventListener("mouseleave", function() {
        card.style.setProperty("--mx", "0px");
        card.style.setProperty("--my", "0px");
      });
    });
  })();
</script>
