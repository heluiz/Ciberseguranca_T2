'use strict';
for (const link of document.querySelectorAll('.sidebar nav a')) {
  if (link.pathname === location.pathname) {
    link.classList.add('active');
    link.setAttribute('aria-current', 'page');
  }
}

// A preferência é visual e local; não envia dados nem altera o inventário.
const themeSelector = document.getElementById('theme-select');
if (themeSelector) {
  const validThemes = new Set(['neon', 'sniper', 'ninjatrader', 'campo']);
  const applyTheme = (value, persist = false) => {
    const theme = validThemes.has(value) ? value : 'neon';
    document.documentElement.dataset.theme = theme;
    themeSelector.value = theme;
    let saved = true;
    if (persist) {
      try { localStorage.setItem('sentinel.theme', theme); } catch (_) { saved = false; }
      const label = themeSelector.selectedOptions[0].textContent;
      document.getElementById('theme-status').textContent = `Tema ${label} aplicado${saved ? '.' : '; a gravação da preferência está indisponível neste navegador.'}`;
    }
  };
  applyTheme(document.documentElement.dataset.theme);
  themeSelector.addEventListener('change', () => applyTheme(themeSelector.value, true));
  window.addEventListener('storage', event => {
    if (event.key === 'sentinel.theme') applyTheme(event.newValue);
  });
}

// Fecha ao clicar fora; Escape devolve o foco à configuração.
const appearanceSettings = document.querySelector('.appearance-settings');
if (appearanceSettings) {
  document.addEventListener('click', event => {
    if (!appearanceSettings.contains(event.target)) appearanceSettings.open = false;
  });
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && appearanceSettings.open) {
      appearanceSettings.open = false;
      appearanceSettings.querySelector('summary').focus();
    }
  });
}
