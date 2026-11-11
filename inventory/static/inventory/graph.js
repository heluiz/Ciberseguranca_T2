'use strict';
async function startGraph() {
  const status = document.getElementById('graph-status');
  try {
    const response = await fetch('/api/grafo/', {headers: {'Accept': 'application/json'}, credentials: 'same-origin'});
    if (!response.ok) throw new Error(`Não foi possível carregar o mapa (${response.status}).`);
    const payload = await response.json();
    if (typeof cytoscape !== 'function') throw new Error('Biblioteca do mapa indisponível.');
    const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
    const cy = cytoscape({container: document.getElementById('graph'), elements: payload.elements,
      layout: {name: 'cose', animate: !reduced, nodeRepulsion: () => 12000, idealEdgeLength: () => 130},
      minZoom: .2, maxZoom: 3,
      style: [
        {selector: 'node', style: {'background-color': '#143f41', 'border-color': '#4de4d2', 'border-width': 2, width: 52, height: 52, label: 'data(label)', color: '#deedf8', 'font-size': 10, 'text-valign': 'bottom', 'text-margin-y': 10, 'text-outline-color': '#080e18', 'text-outline-width': 2}},
        {selector: 'edge', style: {width: 1.5, 'line-color': '#536586', 'target-arrow-color': '#9c8bdc', 'target-arrow-shape': 'triangle', 'curve-style': 'bezier', label: 'data(label)', color: '#acb5c8', 'font-size': 9, 'text-background-color': '#0b1422', 'text-background-opacity': 1, 'text-background-padding': 3}},
        {selector: 'node:selected', style: {'background-color': '#3c3171', 'border-color': '#b39aff', 'border-width': 4}},
        {selector: '.dimmed', style: {opacity: .15}}
      ]});
    status.textContent = `${cy.nodes().length} ativos · ${cy.edges().length} dependências. Consulte as tabelas para uma visualização acessível.`;
    document.getElementById('fit-graph').addEventListener('click', () => cy.fit(undefined, 55));
    document.getElementById('graph-search').addEventListener('input', event => {
      const term = event.target.value.trim().toLowerCase();
      cy.nodes().forEach(node => node.toggleClass('dimmed', Boolean(term) && !node.data('label').toLowerCase().includes(term)));
    });
    cy.on('tap', 'node', event => {
      const node = event.target.data();
      document.getElementById('node-name').textContent = node.label;
      document.getElementById('node-type').textContent = `${node.tipo} · ${node.setor}`;
      const detail = document.getElementById('node-detail');
      detail.replaceChildren();
      for (const [label, value] of [['Risco próprio', node.proprio.toFixed(2)], ['Risco efetivo', node.risco.toFixed(2)], ['Vulnerabilidades', node.falhas]]) {
        const dt = document.createElement('dt'), dd = document.createElement('dd');
        dt.textContent = label; dd.textContent = String(value); detail.append(dt, dd);
      }
    });
    cy.on('layoutstop', () => cy.fit(undefined, 55));
  } catch (error) { status.textContent = error.message; }
}
startGraph();
