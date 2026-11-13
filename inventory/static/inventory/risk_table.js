'use strict';
/*
 * Tabela dinâmica de risco: busca os dados na API (Fetch + async/await),
 * guarda as linhas em um array de objetos e redesenha a tabela a cada
 * filtro ou ordenação com filter, sort e map. Sem JavaScript, a página
 * continua mostrando a mesma tabela, montada pelo servidor.
 */
(async function startRiskTable() {
  const table = document.getElementById('risk-table');
  if (!table) return;
  const body = table.querySelector('tbody');
  const status = document.getElementById('risk-status');
  const textFilter = document.getElementById('risk-filter');
  const typeFilter = document.getElementById('risk-type');
  const sortButtons = [...table.querySelectorAll('.sort-button')];
  const number = new Intl.NumberFormat('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const state = { rows: [], sort: 'efetivo', descending: true };

  // Compara sem diferenciar maiúsculas nem acentos.
  const plain = text => text.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();

  function visibleRows() {
    const term = plain(textFilter.value.trim());
    const type = typeFilter.value;
    return state.rows
      .filter(row => !type || row.tipo === type)
      .filter(row => !term || plain(row.hostname).includes(term) || plain(row.lotacao).includes(term))
      .sort((a, b) => {
        const order = typeof a[state.sort] === 'string'
          ? a[state.sort].localeCompare(b[state.sort], 'pt-BR')
          : a[state.sort] - b[state.sort];
        return state.descending ? -order : order;
      });
  }

  function cell(text, className) {
    const td = document.createElement('td');
    if (className) {
      const span = document.createElement('span');
      span.className = className;
      span.textContent = text;
      td.append(span);
    } else {
      td.textContent = text;
    }
    return td;
  }

  function rowElement(row) {
    const tr = document.createElement('tr');
    const name = document.createElement('td');
    const strong = document.createElement('strong');
    if (row.ficha_url) {
      const link = document.createElement('a');
      link.href = row.ficha_url;
      link.textContent = row.hostname;
      strong.append(link);
    } else {
      strong.textContent = row.hostname;
    }
    const type = document.createElement('small');
    type.textContent = row.tipo;
    name.append(strong, type);
    tr.append(
      name,
      cell(row.lotacao),
      cell(number.format(row.soma_cvss)),
      cell(number.format(row.fator)),
      cell(number.format(row.proprio)),
      cell(number.format(row.herdado)),
      cell(number.format(row.efetivo), 'risk-number'),
    );
    return tr;
  }

  function render() {
    const rows = visibleRows();
    // textContent e createElement: nenhum dado do inventário é interpretado como HTML.
    body.replaceChildren(...rows.map(rowElement));
    if (!rows.length) {
      const tr = document.createElement('tr');
      const td = cell('Nenhum equipamento corresponde ao filtro.');
      td.colSpan = 7;
      tr.append(td);
      body.append(tr);
    }
    const sum = rows.reduce((total, row) => total + row.efetivo, 0);
    status.textContent = `${rows.length} de ${state.rows.length} equipamentos · risco efetivo somado: ${number.format(sum)} pontos`;
    for (const button of sortButtons) {
      const header = button.closest('th');
      if (button.dataset.sort === state.sort) {
        header.setAttribute('aria-sort', state.descending ? 'descending' : 'ascending');
      } else {
        header.removeAttribute('aria-sort');
      }
    }
  }

  try {
    const response = await fetch(table.dataset.source, { headers: { Accept: 'application/json' }, credentials: 'same-origin' });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Resposta ${response.status}`);
    state.rows = payload.rows;
  } catch (error) {
    // A tabela do servidor permanece na tela; só os filtros ficam indisponíveis.
    status.textContent = `Filtros indisponíveis (${error.message}). A tabela abaixo veio do servidor.`;
    return;
  }

  for (const type of [...new Set(state.rows.map(row => row.tipo))].sort((a, b) => a.localeCompare(b, 'pt-BR'))) {
    typeFilter.append(new Option(type, type));
  }
  textFilter.addEventListener('input', render);
  typeFilter.addEventListener('change', render);
  for (const button of sortButtons) {
    button.addEventListener('click', () => {
      if (state.sort === button.dataset.sort) {
        state.descending = !state.descending;
      } else {
        state.sort = button.dataset.sort;
        state.descending = button.dataset.sort !== 'hostname';
      }
      render();
    });
  }
  render();
})();
