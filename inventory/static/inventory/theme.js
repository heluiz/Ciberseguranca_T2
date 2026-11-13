/* Executado antes do CSS para restaurar o tema sem piscar a paleta padrão. */
'use strict';
(() => {
  const themes = ['neon', 'sniper', 'ninjatrader', 'campo'];
  let saved = 'neon';
  try { saved = localStorage.getItem('sentinel.theme') || 'neon'; } catch (_) { /* Preferência opcional. */ }
  document.documentElement.dataset.theme = themes.includes(saved) ? saved : 'neon';
})();
