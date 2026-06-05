/* ═══════════════════════════════════════════════════════════════════════
   AuditGraph Docs — SPA Application
   ═══════════════════════════════════════════════════════════════════════ */

(function () {
  'use strict';

  // ── 1. Config ──────────────────────────────────────────────────────
  const CONTENT_BASE = 'content/';

  const NAV = [
    {
      section: 'Trust',
      icon: '🛡',
      color: '#0ea5e9',
      pages: [
        { slug: 'trust', title: 'Trust Center' },
      ],
    },
    {
      section: 'Getting Started',
      icon: '🚀',
      color: '#2563eb',
      pages: [
        { slug: 'introduction', title: 'Introduction' },
        { slug: 'quick-start', title: 'Quick Start Guide' },
      ],
    },
    {
      section: 'Architecture',
      icon: '🏗',
      color: '#8b5cf6',
      pages: [
        { slug: 'architecture', title: 'Platform Architecture' },
        { slug: 'identity-graph', title: 'Identity Graph' },
        { slug: 'data-model', title: 'Data Model' },
      ],
    },
    {
      section: 'Security',
      icon: '🔒',
      color: '#10b981',
      pages: [
        { slug: 'security-overview', title: 'Security Overview' },
        { slug: 'security-data-protection', title: 'Data Protection' },
        { slug: 'security-architecture', title: 'Security Architecture' },
        { slug: 'security-features', title: 'Security Features' },
        { slug: 'security-vendor-faq', title: 'Vendor Security FAQ' },
        { slug: 'security-posture', title: 'Security Posture' },
      ],
    },
    {
      section: 'Governance',
      icon: '⚖',
      color: '#f59e0b',
      pages: [
        { slug: 'risk-scoring', title: 'Risk Scoring (AGIRS)' },
        { slug: 'ai-agent-governance', title: 'AI Agent Governance' },
        { slug: 'compliance', title: 'Compliance Mapping' },
        { slug: 'best-practices', title: 'Best Practices' },
      ],
    },
    {
      section: 'Operations',
      icon: '⚙',
      color: '#6366f1',
      pages: [
        { slug: 'connectors', title: 'Connectors' },
        { slug: 'discovery-engine', title: 'Discovery Engine' },
        { slug: 'operations', title: 'Operations' },
      ],
    },
    {
      section: 'Reference',
      icon: '📖',
      color: '#dc2626',
      pages: [
        { slug: 'api-reference', title: 'API Reference' },
        { slug: 'glossary', title: 'Glossary' },
        { slug: 'faq', title: 'FAQ' },
      ],
    },
  ];

  // Flatten for lookup
  const PAGE_MAP = {};
  NAV.forEach(function (group) {
    group.pages.forEach(function (p) {
      PAGE_MAP[p.slug] = p;
    });
  });

  // ── 2. DOM refs ────────────────────────────────────────────────────
  const $ = function (id) { return document.getElementById(id); };
  const sidebarEl    = $('sidebar');
  const sidebarNav   = $('sidebar-nav');
  const overlay      = $('sidebar-overlay');
  const hamburger    = $('hamburger');
  const contentEl    = $('content');
  const articleEl    = $('article');
  const skeletonEl   = $('skeleton');
  const tocList      = $('toc-list');
  const tocRail      = $('toc-rail');
  const searchInput  = $('search-input');
  const searchResults = $('search-results');

  // ── 3. Sidebar Renderer ────────────────────────────────────────────
  function renderSidebar() {
    var html = '';
    NAV.forEach(function (group) {
      html += '<div class="nav-section">';
      html += '<div class="nav-section-header">';
      html += '<span class="nav-section-icon" style="background:' + group.color + '22;color:' + group.color + '">' + group.icon + '</span>';
      html += group.section;
      html += '</div>';
      group.pages.forEach(function (p) {
        html += '<a class="nav-link" href="#/' + p.slug + '" data-slug="' + p.slug + '">' + p.title + '</a>';
      });
      html += '</div>';
    });
    sidebarNav.innerHTML = html;
  }

  function setActiveNav(slug) {
    var links = sidebarNav.querySelectorAll('.nav-link');
    links.forEach(function (el) {
      if (el.dataset.slug === slug) {
        el.classList.add('active');
      } else {
        el.classList.remove('active');
      }
    });
  }

  // Mobile sidebar toggle
  function toggleSidebar() {
    var isOpen = sidebarEl.classList.toggle('open');
    hamburger.classList.toggle('open', isOpen);
    overlay.classList.toggle('visible', isOpen);
  }

  function closeSidebar() {
    sidebarEl.classList.remove('open');
    hamburger.classList.remove('open');
    overlay.classList.remove('visible');
  }

  hamburger.addEventListener('click', toggleSidebar);
  overlay.addEventListener('click', closeSidebar);

  // Close sidebar on nav click (mobile)
  sidebarNav.addEventListener('click', function (e) {
    if (e.target.classList.contains('nav-link') && window.innerWidth < 768) {
      closeSidebar();
    }
  });

  // ── 4. Markdown Renderer ───────────────────────────────────────────

  // ASCII diagram detection
  var ASCII_CHARS = /[┌┐└┘│─├┤┬┴┼═║╔╗╚╝╠╣╦╩╬▶◀▲▼►◄●○■□▸▹→←↑↓↔⟶⟵⟷┃┏┓┗┛]/;

  // API endpoint pattern
  var API_RE = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\/\S+)/;

  // Configure marked
  var renderer = new marked.Renderer();

  // Headings with anchor links
  renderer.heading = function (text, level, raw) {
    // marked v12: arguments might be different, handle both
    if (typeof text === 'object') {
      raw = text.raw || text.text;
      level = text.depth;
      text = text.text;
    }
    var id = (raw || text).toLowerCase().replace(/<[^>]*>/g, '').replace(/[^\w\s-]/g, '').replace(/\s+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
    return '<h' + level + ' id="' + id + '">' + text +
      '<a class="heading-anchor" href="#' + id + '" title="Copy link" onclick="copyAnchor(event, \'' + id + '\')">#</a>' +
      '</h' + level + '>';
  };

  // Tables wrapped for scroll
  renderer.table = function (header, body) {
    // marked v12 object form
    if (typeof header === 'object' && header.header !== undefined) {
      body = header.rows.map(function(row) {
        var cells = row.map(function(cell) {
          return '<td>' + cell.text + '</td>';
        }).join('');
        return '<tr>' + cells + '</tr>';
      }).join('');
      header = '<tr>' + header.header.map(function(h) {
        return '<th>' + h.text + '</th>';
      }).join('') + '</tr>';
      return '<div class="table-wrapper"><table><thead>' + header + '</thead><tbody>' + body + '</tbody></table></div>';
    }
    return '<div class="table-wrapper"><table><thead>' + header + '</thead><tbody>' + body + '</tbody></table></div>';
  };

  // Code blocks with language badges + ASCII diagram detection
  renderer.code = function (code, lang) {
    // marked v12 object form
    if (typeof code === 'object') {
      lang = code.lang;
      code = code.text;
    }

    // ASCII diagram detection
    if (ASCII_CHARS.test(code)) {
      return '<pre class="ascii-diagram"><code>' + escapeHtml(code) + '</code></pre>';
    }

    // API endpoint blocks — detect lines like "GET /api/..."
    var lines = code.split('\n');
    var apiLines = [];
    var nonApiLines = [];
    lines.forEach(function (line) {
      var m = line.match(API_RE);
      if (m) {
        apiLines.push({ method: m[1], path: m[2] });
      } else if (line.trim()) {
        nonApiLines.push(line);
      }
    });

    // If most lines are API endpoints, render as cards
    if (apiLines.length > 0 && apiLines.length >= nonApiLines.length) {
      var html = '';
      apiLines.forEach(function (ep) {
        html += '<div class="api-endpoint">';
        html += '<span class="api-method ' + ep.method.toLowerCase() + '">' + ep.method + '</span>';
        html += '<span class="api-path">' + escapeHtml(ep.path) + '</span>';
        html += '</div>';
      });
      return html;
    }

    // Normal code block
    var highlighted = code;
    if (lang && hljs.getLanguage(lang)) {
      try {
        highlighted = hljs.highlight(code, { language: lang }).value;
      } catch (e) { /* ignore */ }
    } else {
      try {
        highlighted = hljs.highlightAuto(code).value;
      } catch (e) { /* ignore */ }
    }

    var badge = lang ? '<span class="code-lang-badge">' + escapeHtml(lang) + '</span>' : '';
    return '<div class="code-block-wrapper">' + badge +
      '<pre><code class="hljs">' + highlighted + '</code></pre></div>';
  };

  // Rewrite .md links to hash routes
  renderer.link = function (href, title, text) {
    // marked v12 object form
    if (typeof href === 'object') {
      text = href.text;
      title = href.title;
      href = href.href;
    }
    if (href && href.endsWith('.md')) {
      var slug = href.replace(/\.md$/, '').replace(/^.*\//, '');
      href = '#/' + slug;
    }
    var titleAttr = title ? ' title="' + escapeHtml(title) + '"' : '';
    var external = href && href.startsWith('http') ? ' target="_blank" rel="noopener"' : '';
    return '<a href="' + href + '"' + titleAttr + external + '>' + text + '</a>';
  };

  marked.setOptions({
    renderer: renderer,
    gfm: true,
    breaks: false,
  });

  function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // Post-process: callout boxes from blockquotes
  function postProcessCallouts(html) {
    // Convert blockquotes starting with **Note:**, **Warning:**, **Tip:**, **Important:**, **Danger:**
    return html.replace(/<blockquote>\s*<p>\s*<strong>(Note|Warning|Tip|Important|Danger):?\s*<\/strong>/gi, function (match, type) {
      var cls = type.toLowerCase();
      if (cls === 'important') cls = 'danger';
      return '<div class="callout ' + cls + '"><p><span class="callout-title">' + type + ':</span> ';
    }).replace(/<\/blockquote>/g, function () {
      // Only close callout divs that we opened
      return '</div>';
    });
  }

  // ── 5. Page Loader ─────────────────────────────────────────────────
  var currentSlug = null;

  function loadPage(slug) {
    if (!slug || !PAGE_MAP[slug]) {
      show404();
      return;
    }

    currentSlug = slug;
    setActiveNav(slug);

    // Show skeleton
    skeletonEl.classList.remove('hidden');
    articleEl.classList.remove('loaded');

    // Update document title
    document.title = PAGE_MAP[slug].title + ' — AuditGraph Docs';

    fetch(CONTENT_BASE + slug + '.md')
      .then(function (res) {
        if (!res.ok) throw new Error('Not found');
        return res.text();
      })
      .then(function (md) {
        var html = marked.parse(md);
        html = postProcessCallouts(html);
        articleEl.innerHTML = html;

        skeletonEl.classList.add('hidden');
        articleEl.classList.add('loaded');

        buildTOC();
        initScrollSpy();

        // Scroll to top or anchor
        var hashParts = window.location.hash.split('#');
        if (hashParts.length > 2) {
          var anchor = hashParts[2];
          var el = document.getElementById(anchor);
          if (el) {
            setTimeout(function () { el.scrollIntoView({ behavior: 'smooth' }); }, 100);
            return;
          }
        }
        contentEl.scrollTop = 0;
        window.scrollTo(0, 0);
      })
      .catch(function () {
        show404();
      });
  }

  function show404() {
    skeletonEl.classList.add('hidden');
    var tpl = document.getElementById('not-found-tpl');
    articleEl.innerHTML = tpl.innerHTML;
    articleEl.classList.add('loaded');
    tocList.innerHTML = '';
    document.title = '404 — AuditGraph Docs';
  }

  // ── 6. TOC Generator ──────────────────────────────────────────────
  function buildTOC() {
    var headings = articleEl.querySelectorAll('h2, h3');
    var html = '';
    headings.forEach(function (h) {
      var level = h.tagName === 'H3' ? 'toc-h3' : '';
      var id = h.id;
      var text = h.textContent.replace(/#$/, '').trim();
      html += '<li><a href="#' + id + '" class="' + level + '" data-id="' + id + '">' + text + '</a></li>';
    });
    tocList.innerHTML = html;
  }

  // ── 7. Scroll Spy ─────────────────────────────────────────────────
  var observer = null;

  function initScrollSpy() {
    if (observer) observer.disconnect();

    var headings = articleEl.querySelectorAll('h2, h3');
    if (!headings.length) return;

    observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          var id = entry.target.id;
          var tocLinks = tocList.querySelectorAll('a');
          tocLinks.forEach(function (a) {
            a.classList.toggle('active', a.dataset.id === id);
          });
        }
      });
    }, {
      rootMargin: '-80px 0px -60% 0px',
      threshold: 0,
    });

    headings.forEach(function (h) { observer.observe(h); });
  }

  // ── 8. Search (lunr.js) ───────────────────────────────────────────
  var searchIndex = null;
  var searchDocs = {};
  var indexBuilding = false;

  function buildSearchIndex() {
    if (searchIndex || indexBuilding) return Promise.resolve();
    indexBuilding = true;

    var allPages = [];
    NAV.forEach(function (group) {
      group.pages.forEach(function (p) {
        allPages.push(p);
      });
    });

    var fetches = allPages.map(function (p) {
      return fetch(CONTENT_BASE + p.slug + '.md')
        .then(function (r) { return r.ok ? r.text() : ''; })
        .then(function (text) {
          searchDocs[p.slug] = { title: p.title, body: text, slug: p.slug };
        })
        .catch(function () {});
    });

    return Promise.all(fetches).then(function () {
      searchIndex = lunr(function () {
        this.ref('slug');
        this.field('title', { boost: 10 });
        this.field('body');

        var self = this;
        Object.keys(searchDocs).forEach(function (slug) {
          self.add(searchDocs[slug]);
        });
      });
      indexBuilding = false;
    });
  }

  function doSearch(query) {
    if (!searchIndex || !query.trim()) {
      searchResults.classList.remove('visible');
      return;
    }

    var results;
    try {
      results = searchIndex.search(query + '~1'); // fuzzy
    } catch (e) {
      try {
        results = searchIndex.search(query);
      } catch (e2) {
        results = [];
      }
    }

    if (!results.length) {
      searchResults.innerHTML = '<div class="search-no-results">No results for "' + escapeHtml(query) + '"</div>';
      searchResults.classList.add('visible');
      return;
    }

    var html = '';
    results.slice(0, 8).forEach(function (r) {
      var doc = searchDocs[r.ref];
      if (!doc) return;

      // Extract snippet
      var snippet = extractSnippet(doc.body, query);

      html += '<div class="search-result-item" data-slug="' + doc.slug + '">';
      html += '<div class="search-result-title">' + escapeHtml(doc.title) + '</div>';
      html += '<div class="search-result-snippet">' + snippet + '</div>';
      html += '</div>';
    });

    searchResults.innerHTML = html;
    searchResults.classList.add('visible');
  }

  function extractSnippet(body, query) {
    var words = query.toLowerCase().split(/\s+/);
    var lines = body.split('\n');
    var best = '';
    var bestScore = 0;

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].replace(/^#+\s*/, '').replace(/[*_`\[\]()]/g, '');
      if (line.length < 10) continue;
      var lower = line.toLowerCase();
      var score = 0;
      words.forEach(function (w) {
        if (lower.indexOf(w) !== -1) score++;
      });
      if (score > bestScore) {
        bestScore = score;
        best = line;
      }
    }

    if (!best) best = lines.find(function (l) { return l.length > 20; }) || '';

    // Truncate
    if (best.length > 160) best = best.substring(0, 160) + '…';

    // Highlight
    words.forEach(function (w) {
      if (!w) return;
      var re = new RegExp('(' + w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
      best = best.replace(re, '<mark>$1</mark>');
    });

    return best;
  }

  // Search event handlers
  searchInput.addEventListener('focus', function () {
    buildSearchIndex();
  });

  searchInput.addEventListener('input', function () {
    var q = searchInput.value;
    if (q.length < 2) {
      searchResults.classList.remove('visible');
      return;
    }
    buildSearchIndex().then(function () {
      doSearch(q);
    });
  });

  // Click on search result
  searchResults.addEventListener('click', function (e) {
    var item = e.target.closest('.search-result-item');
    if (item) {
      window.location.hash = '#/' + item.dataset.slug;
      searchInput.value = '';
      searchResults.classList.remove('visible');
      searchInput.blur();
    }
  });

  // Close search on outside click
  document.addEventListener('click', function (e) {
    if (!e.target.closest('#search-wrapper')) {
      searchResults.classList.remove('visible');
    }
  });

  // Keyboard: / to focus search, Escape to close
  document.addEventListener('keydown', function (e) {
    if (e.key === '/' && document.activeElement !== searchInput) {
      e.preventDefault();
      searchInput.focus();
      buildSearchIndex();
    }
    if (e.key === 'Escape') {
      searchResults.classList.remove('visible');
      searchInput.blur();
    }
  });

  // Keyboard navigation in search results
  searchInput.addEventListener('keydown', function (e) {
    var items = searchResults.querySelectorAll('.search-result-item');
    if (!items.length) return;

    var active = searchResults.querySelector('.search-result-item.active');
    var idx = -1;
    if (active) {
      idx = Array.prototype.indexOf.call(items, active);
    }

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (active) active.classList.remove('active');
      idx = (idx + 1) % items.length;
      items[idx].classList.add('active');
      items[idx].scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (active) active.classList.remove('active');
      idx = idx <= 0 ? items.length - 1 : idx - 1;
      items[idx].classList.add('active');
      items[idx].scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'Enter') {
      if (active) {
        e.preventDefault();
        window.location.hash = '#/' + active.dataset.slug;
        searchInput.value = '';
        searchResults.classList.remove('visible');
        searchInput.blur();
      }
    }
  });

  // ── 9. Router ──────────────────────────────────────────────────────
  function getSlugFromHash() {
    var hash = window.location.hash;
    if (!hash || hash === '#' || hash === '#/') return 'introduction';
    // Handle #/slug and #/slug#anchor
    var path = hash.replace(/^#\/?/, '').split('#')[0];
    return path || 'introduction';
  }

  function onRoute() {
    var slug = getSlugFromHash();
    if (slug !== currentSlug) {
      loadPage(slug);
    }
  }

  window.addEventListener('hashchange', onRoute);

  // ── 10. Copy anchor ────────────────────────────────────────────────
  window.copyAnchor = function (e, id) {
    e.preventDefault();
    e.stopPropagation();
    var url = window.location.origin + window.location.pathname + '#/' + currentSlug + '#' + id;
    if (navigator.clipboard) {
      navigator.clipboard.writeText(url);
    }
    // Visual feedback
    var el = e.target;
    var orig = el.textContent;
    el.textContent = '✓';
    setTimeout(function () { el.textContent = orig; }, 1500);
  };

  // ── 11. TOC click handler ──────────────────────────────────────────
  tocList.addEventListener('click', function (e) {
    if (e.target.tagName === 'A') {
      e.preventDefault();
      var id = e.target.dataset.id;
      var el = document.getElementById(id);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
        // Update URL without triggering route
        history.replaceState(null, '', '#/' + currentSlug + '#' + id);
      }
    }
  });

  // ── Init ───────────────────────────────────────────────────────────
  renderSidebar();
  onRoute();

})();
