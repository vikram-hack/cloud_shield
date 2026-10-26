/**
 * CloudShield — Main JavaScript
 */
'use strict';

// ── Sidebar Toggle ────────────────────────────────────────────────────────────
(function initSidebar() {
  const sidebar   = document.getElementById('sidebar');
  const topbar    = document.getElementById('topbar');
  const main      = document.getElementById('mainContent');
  const toggle    = document.getElementById('sidebarToggle');
  const menuBtn   = document.getElementById('menuBtn');
  const backdrop  = document.getElementById('sidebarBackdrop');

  if (!sidebar) return;

  const isMobile = () => window.innerWidth <= 992;

  function closeMobileSidebar() {
    sidebar.classList.remove('mobile-open');
    backdrop?.classList.remove('active');
  }

  function toggleSidebar() {
    if (isMobile()) {
      const isOpen = sidebar.classList.toggle('mobile-open');
      backdrop?.classList.toggle('active', isOpen);
    } else {
      const isCollapsed = sidebar.classList.toggle('collapsed');
      topbar?.classList.toggle('sidebar-collapsed', isCollapsed);
      main?.classList.toggle('sidebar-collapsed', isCollapsed);
    }
  }

  // On page load: ensure sidebar is fully open (expanded)
  sidebar.classList.remove('collapsed', 'mobile-open');
  topbar?.classList.remove('sidebar-collapsed');
  main?.classList.remove('sidebar-collapsed');
  backdrop?.classList.remove('active');

  toggle?.addEventListener('click', (e) => { e.preventDefault(); toggleSidebar(); });
  menuBtn?.addEventListener('click', (e) => { e.preventDefault(); toggleSidebar(); });
  backdrop?.addEventListener('click', closeMobileSidebar);

  // Close mobile sidebar when clicking outside
  document.addEventListener('click', (e) => {
    if (isMobile() && sidebar.classList.contains('mobile-open')) {
      if (!sidebar.contains(e.target) && !menuBtn?.contains(e.target)) {
        closeMobileSidebar();
      }
    }
  });

  // Handle window resize: reset state when switching breakpoints
  window.addEventListener('resize', () => {
    if (!isMobile()) {
      closeMobileSidebar();
    } else {
      sidebar.classList.remove('collapsed');
      topbar?.classList.remove('sidebar-collapsed');
      main?.classList.remove('sidebar-collapsed');
    }
  });
})();


// ── Auto-dismiss flash messages ──────────────────────────────────────────────
(function autoDismissFlash() {
  setTimeout(() => {
    document.querySelectorAll('.cs-flash').forEach(el => {
      el.style.transition = 'opacity 0.5s ease';
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 500);
    });
  }, 5000);
})();


// ── Confirm dialogs ───────────────────────────────────────────────────────────
document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-confirm]');
  if (btn) {
    const msg = btn.dataset.confirm || 'Are you sure?';
    if (!confirm(msg)) e.preventDefault();
  }
});


// ── Chart.js global defaults (DarkMinimal Theme) ──────────────────────────────
if (typeof Chart !== 'undefined') {
  Chart.defaults.color = '#A0A0A0';
  Chart.defaults.font.family = "'Montserrat', 'Inter', system-ui, sans-serif";
  Chart.defaults.font.size = 12;

  Chart.defaults.plugins.legend.labels.boxWidth = 10;
  Chart.defaults.plugins.legend.labels.padding = 16;
  Chart.defaults.plugins.tooltip.backgroundColor = '#141414';
  Chart.defaults.plugins.tooltip.borderColor = 'rgba(255, 255, 255, 0.12)';
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.plugins.tooltip.padding = 10;
  Chart.defaults.plugins.tooltip.titleColor = '#FFFFFF';
  Chart.defaults.plugins.tooltip.bodyColor = '#DFDFDF';
  Chart.defaults.plugins.tooltip.cornerRadius = 8;
}


// ── Chart builder helpers ─────────────────────────────────────────────────────
window.CS = window.CS || {};

CS.COLORS = {
  green:  '#A9FF5B', // DarkMinimal Lime Neon
  cyan:   '#A476FF', // DarkMinimal Signature Purple
  teal:   '#6EE7B7',
  red:    '#FF4D6D', // Crimson
  amber:  '#FFC247', // Warm Amber
  orange: '#FF7849', // Coral Orange
  purple: '#A476FF', // DarkMinimal Purple
  blue:   '#80A0FF', // Periwinkle Blue
  muted:  '#666666',
};

CS.SEVERITY_COLORS = {
  critical: '#FF4D6D',
  high:     '#FF7849',
  medium:   '#FFC247',
  low:      '#A9FF5B',
  info:     '#A476FF',
};

CS.gridOpts = (axis) => ({
  grid: {
    color: 'rgba(255, 255, 255, 0.05)',
    drawBorder: false,
  },
  ticks: { color: '#888888', maxTicksLimit: axis === 'y' ? 6 : 8 },
  border: { display: false },
});

CS.lineChart = (ctx, labels, datasets, opts = {}) => new Chart(ctx, {
  type: 'line',
  data: { labels, datasets },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: 'index', intersect: false },
    plugins: { legend: { display: datasets.length > 1 } },
    scales: {
      x: CS.gridOpts('x'),
      y: { ...CS.gridOpts('y'), beginAtZero: true },
    },
    ...opts,
  },
});

CS.barChart = (ctx, labels, data, colors, opts = {}) => new Chart(ctx, {
  type: 'bar',
  data: {
    labels,
    datasets: [{ data, backgroundColor: colors, borderRadius: 5, borderSkipped: false }],
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: CS.gridOpts('x'),
      y: { ...CS.gridOpts('y'), beginAtZero: true },
    },
    ...opts,
  },
});

CS.doughnutChart = (ctx, labels, data, colors) => new Chart(ctx, {
  type: 'doughnut',
  data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 0, hoverOffset: 6 }] },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: { padding: 14, usePointStyle: true, pointStyleWidth: 10 },
      },
    },
    cutout: '72%',
  },
});


// ── Tooltip initialisation (Bootstrap) ───────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  if (typeof bootstrap !== 'undefined') {
    const tooltipEls = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltipEls.forEach(el => new bootstrap.Tooltip(el));
  }
});
