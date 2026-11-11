'use strict';
for (const link of document.querySelectorAll('.sidebar nav a')) {
  if (link.pathname === location.pathname) {
    link.classList.add('active');
    link.setAttribute('aria-current', 'page');
  }
}
