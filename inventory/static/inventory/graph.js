'use strict';
/* Modelo Cytoscape headless e renderização SVG acessível de cartões e conexões. */
async function startGraph() {
  const $ = id => document.getElementById(id);
  const status = $('graph-status'), svg = $('topology');
  const ns = 'http://www.w3.org/2000/svg';
  const sprite = '/static/inventory/icons.svg#';
  const icons = {1:'computer',2:'server',3:'router',4:'printer',5:'code',6:'database',7:'layers'};
  const fmt = value => Number(value).toLocaleString('pt-BR', {minimumFractionDigits:2,maximumFractionDigits:2});
  let cy, nodes, edges, plan, selected, focused, view, originalView, resetView, isAll = false;
  let motion = !matchMedia('(prefers-reduced-motion: reduce)').matches;
  let drag = null;
  const el = (name, attrs = {}, text = null) => {
    const element = document.createElementNS(ns, name);
    for (const [key,value] of Object.entries(attrs)) element.setAttribute(key, String(value));
    if (text !== null) element.textContent = text;
    return element;
  };
  const html = (tag, className, text) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  };
  function icon(name, x, y, size=32) {
    const element = el('svg',{x,y,width:size,height:size,viewBox:'0 0 24 24',class:'node-icon'});
    element.append(el('use',{href:sprite+name}));
    return element;
  }
  function severity(node) {
    const value = node.cvss_maximo;
    if (value >= 9) return ['Crítica','critical'];
    if (value >= 7) return ['Alta','high'];
    if (value >= 4) return ['Média','medium'];
    if (value > 0) return ['Baixa','low'];
    return ['Sem falhas ativas','clear'];
  }
  function setView(box) {
    view = box;
    svg.setAttribute('viewBox', `${box.x} ${box.y} ${box.w} ${box.h}`);
  }
  function updateMotion() {
    $('graph').classList.toggle('effects-paused', !motion);
    $('motion-toggle').setAttribute('aria-pressed', String(!motion));
    $('motion-toggle').setAttribute('aria-label', motion ? 'Pausar efeitos visuais' : 'Ativar efeitos visuais');
    $('motion-toggle').querySelector('use').setAttribute('href', sprite+(motion?'pause':'play'));
  }
  function showInspector(node) {
    selected = node;
    $('node-name').textContent = node.label;
    $('node-type').textContent = node.tipo;
    $('node-owner').textContent = node.custodiante;
    $('node-sector').textContent = node.setor;
    $('risk-own').textContent = fmt(node.proprio);
    $('risk-inherited').textContent = fmt(node.herdado);
    $('risk-effective').textContent = fmt(node.risco);
    $('inspector-icon').querySelector('use').setAttribute('href', sprite+icons[node.tipo_id]);
    $('asset-sheet').href = node.ficha_url;
    $('simulate-fix').disabled = false;
    $('simulation-result').hidden = true;
    const container = $('node-findings'); container.replaceChildren();
    const active = node.vulnerabilidades.filter(v => !v.corrigida);
    if (!active.length) container.append(html('p','empty-findings','Nenhuma vulnerabilidade ativa neste equipamento.'));
    for (const vuln of active.slice(0,3)) {
      const card = html('article','finding-card');
      const sign = html('span','finding-sign','△');
      const body = html('div','finding-text');
      body.append(html('strong','',vuln.cve || vuln.descricao));
      body.append(html('small','',vuln.cve ? vuln.descricao : vuln.situacao));
      const badge = html('span', 'severity-badge '+severity({cvss_maximo:vuln.cvss})[1], `${vuln.cvss.toFixed(1)}`);
      badge.title = 'CVSS · '+vuln.gravidade;
      card.append(sign,body,badge); container.append(card);
    }
    if (active.length > 3) container.append(html('small','more-findings',`+ ${active.length-3} ocorrências na ficha completa`));
    for (const element of svg.querySelectorAll('.asset-node')) {
      element.classList.toggle('is-selected', element.dataset.id === node.id);
      element.setAttribute('aria-pressed', String(element.dataset.id === node.id));
    }
    const inheritance=$('inheritance-sources');inheritance.replaceChildren();
    if(node.contribuicoes.length){
      inheritance.append(html('h4','','Risco herdado de'));
      for(const source of node.contribuicoes.slice(0,3)){
        const row=html('p','');row.append(html('span','',source.hostname),html('strong','',fmt(source.pontos)+' pts'));inheritance.append(row);
      }
    }
    // As prioridades são globais; seleção não muda silenciosamente o critério.
  }
  function priorities() {
    const tbody = $('priority-rows'); tbody.replaceChildren();
    for (const [index, fix] of plan.slice(0,3).entries()) {
      const row = html('tr','');
      row.append(html('td','',String(index+1)));
      const assetCell = html('td','priority-asset');
      const link = html('a','',fix.asset); link.href = '/ativos/'+fix.asset_id+'/'; assetCell.append(link);
      row.append(assetCell, html('td','priority-vuln',fix.vulnerability));
      const actionCell = html('td','');
      const action = html('a','','Revisar tratamento →'); action.href='/registros/finding/?q='+encodeURIComponent(fix.asset);
      actionCell.append(action); row.append(actionCell,html('td','priority-reduction','↓ −'+fmt(fix.reducao)+' pontos'));
      tbody.append(row);
    }
    if (!plan.length) {
      const row=html('tr',''), cell=html('td','','Não há correções pendentes no modelo.');
      cell.colSpan=5;row.append(cell);tbody.append(row);
    }
  }
  function setupDefs() {
    const defs=el('defs');
    const gradient=el('linearGradient',{id:'card-fill',x1:'0',y1:'0',x2:'1',y2:'1'});
    gradient.append(el('stop',{offset:'0%','stop-color':'#22203f'}),el('stop',{offset:'50%','stop-color':'#0b1426'}),el('stop',{offset:'100%','stop-color':'#080d1b'}));
    const selectedGradient=el('linearGradient',{id:'selected-fill',x1:'0',y1:'0',x2:'1',y2:'1'});
    selectedGradient.append(el('stop',{offset:'0%','stop-color':'#153b49'}),el('stop',{offset:'100%','stop-color':'#09172a'}));
    defs.append(gradient,selectedGradient);
    for (const color of ['cyan','purple']) {
      const marker=el('marker',{id:'arrow-'+color,viewBox:'0 0 10 10',refX:8,refY:5,markerWidth:7,markerHeight:7,orient:'auto'});
      marker.append(el('path',{d:'M 0 1 L 9 5 L 0 9 Z',fill:color==='cyan'?'#19efff':'#d282ff'}));defs.append(marker);
    }
    svg.append(defs);
  }
  function focusLayout() {
    const incoming=edges.filter(e=>e.target===focused.id).sort((a,b)=>b.fracao-a.fracao);
    const outgoing=edges.filter(e=>e.source===focused.id).sort((a,b)=>b.fracao-a.fracao);
    const used=new Set([focused.id]);
    const left=[],right=[],last=[];
    for (const edge of incoming) if (!used.has(edge.source) && left.length<4) {used.add(edge.source);left.push(nodes.get(edge.source));}
    for (const edge of outgoing) if (!used.has(edge.target) && right.length<4) {used.add(edge.target);right.push(nodes.get(edge.target));}
    // Contexto de segundo nível, sempre com relações realmente cadastradas.
    for (const edge of edges) {
      const candidate=used.has(edge.source) && !used.has(edge.target) ? edge.target : used.has(edge.target) && !used.has(edge.source) ? edge.source : null;
      if (candidate && last.length<3) {used.add(candidate);last.push(nodes.get(candidate));}
    }
    const positions=new Map([[focused.id,{x:420,y:240}]]);
    const column=(list,x)=>list.forEach((node,i)=>positions.set(node.id,{x,y:100+i*(list.length>3?90:135)+(3-list.length)*20}));
    column(left,125);column(right,700);column(last,970);
    return positions;
  }
  function allLayout() {
    const sorted=[...nodes.values()].sort((a,b)=>a.tipo_id-b.tipo_id || a.label.localeCompare(b.label));
    return new Map(sorted.map((node,i)=>[node.id,{x:130+(i%5)*260,y:100+Math.floor(i/5)*145}]));
  }
  function drawMap() {
    svg.replaceChildren();setupDefs();
    const positions=isAll?allLayout():focusLayout();
    const maxY=Math.max(520,...[...positions.values()].map(p=>p.y+80));
    originalView={x:0,y:0,w:isAll?1320:1100,h:maxY};
    const focusPosition=positions.get(focused.id);
    resetView=!isAll && matchMedia('(max-width: 500px)').matches
      ? {x:focusPosition.x-280,y:focusPosition.y-225,w:560,h:450} : {...originalView};
    setView({...resetView});
    const direct=new Set([focused.id]);
    for(const edge of edges){if(edge.source===focused.id)direct.add(edge.target);if(edge.target===focused.id)direct.add(edge.source);}
    const context=new Set();
    if(!isAll)for(const id of positions.keys()){
      if(direct.has(id))continue;
      const relation=edges.filter(e=>(e.source===id && direct.has(e.target))||(e.target===id && direct.has(e.source))).sort((a,b)=>b.fracao-a.fracao)[0];
      if(relation)context.add(relation.id);
    }
    const lines=el('g',{class:'connection-layer'}),cards=el('g',{class:'card-layer'});
    for (const edge of edges) {
      if (!positions.has(edge.source)||!positions.has(edge.target)) continue;
      if(!isAll && edge.source!==focused.id && edge.target!==focused.id && !context.has(edge.id))continue;
      const s=positions.get(edge.source),t=positions.get(edge.target);
      const direction=t.x>=s.x?1:-1;
      const x1=s.x+direction*96,x2=t.x-direction*104;
      const curve=Math.max(45,Math.abs(x2-x1)*.5);
      const reverse=edges.some(other=>other.source===edge.target && other.target===edge.source);
      const arc=reverse?(Number(edge.source)<Number(edge.target)?-32:32):0;
      const d=`M${x1},${s.y} C${x1+direction*curve},${s.y+arc} ${x2-direction*curve},${t.y+arc} ${x2},${t.y}`;
      const color=edge.source===focused.id || edge.target===focused.id ? 'cyan':'purple';
      const group=el('g',{class:'connection '+color});
      group.append(el('path',{d,class:'wire-halo'}),el('path',{d,class:'wire-line','marker-end':'url(#arrow-'+color+')'}));
      if (!isAll) group.append(el('path',{d,class:'wire-flow'}));
      const cx=(x1+x2)/2,cy=(s.y+t.y)/2+arc*.75;
      group.append(el('rect',{x:cx-25,y:cy-12,width:50,height:23,rx:5,class:'edge-label-bg'}),el('text',{x:cx,y:cy+4,class:'edge-label'},(edge.fracao*100).toLocaleString('pt-BR',{maximumFractionDigits:2})+'%'));
      lines.append(group);
    }
    for (const [id, position] of positions) {
      const node=nodes.get(id),[severityText,severityClass]=severity(node);
      const g=el('g',{transform:`translate(${position.x-99},${position.y-43})`,class:'asset-node'+(id===selected.id?' is-selected':''),role:'button',tabindex:0,'aria-label':`${node.label}, ${node.tipo}, CVSS máximo ${node.cvss_maximo}`, 'aria-pressed':String(id===selected.id)});
      g.dataset.id=id;
      g.append(el('rect',{x:-3,y:-3,width:204,height:92,rx:13,class:'node-halo'}),el('rect',{width:198,height:86,rx:11,class:'node-card'}));
      g.append(icon(icons[node.tipo_id],15,23,35));
      const title=el('text',{x:64,y:24,class:'node-hostname'},node.label.length>19?node.label.slice(0,18)+'…':node.label);
      g.append(title,el('text',{x:64,y:43,class:'node-kind'},node.tipo.length>22?node.tipo.slice(0,21)+'…':node.tipo));
      const badgeWidth=Math.min(127,Math.max(55,severityText.length*6+21));
      g.append(el('rect',{x:64,y:53,width:badgeWidth,height:21,rx:7,class:'node-severity-bg '+severityClass}),el('text',{x:73,y:68,class:'node-severity-text '+severityClass},severityText));
      const choose=()=>showInspector(node);
      g.addEventListener('click',choose);
      g.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();choose();}});
      g.addEventListener('dblclick',()=>{focused=node;isAll=false;$('graph-scope').value='focus';drawMap();});
      cards.append(g);
    }
    svg.append(lines,cards);
    status.textContent=`${nodes.size} ativos · ${edges.length} dependências · ${positions.size} visíveis${isAll?' · Visão completa':' · Foco em '+focused.label}`;
  }
  try {
    const response=await fetch('/api/grafo/',{headers:{Accept:'application/json'},credentials:'same-origin'});
    if(!response.ok) throw new Error(`Não foi possível carregar o mapa (${response.status}).`);
    const payload=await response.json();
    cy=cytoscape({headless:true,elements:payload.elements});
    nodes=new Map(cy.nodes().map(n=>[n.id(),n.data()]));
    edges=cy.edges().map(edge=>edge.data());plan=payload.plan;
    $('metric-assets').textContent=nodes.size;$('metric-findings').textContent=payload.open_count;
    $('metric-edges').textContent=edges.length;$('metric-fixes').textContent=plan.length;
    $('graph-loading').hidden=true;priorities();
    if (!nodes.size) {status.textContent='Inventário vazio. Cadastre ou importe seus ativos.';return;}
    const requested=new URLSearchParams(location.search).get('ativo');
    focused=nodes.get(requested)||[...nodes.values()].filter(n=>n.tipo_id===2).sort((a,b)=>cy.getElementById(b.id).degree()-cy.getElementById(a.id).degree() || b.risco-a.risco)[0]||[...nodes.values()][0];
    selected=focused;drawMap();showInspector(selected);updateMotion();
    $('fit-graph').addEventListener('click',()=>setView({...resetView}));
    matchMedia('(max-width: 500px)').addEventListener('change',()=>drawMap());
    function zoom(scale) {const w=view.w*scale,h=view.h*scale;if(w<200||w>originalView.w*2.5)return;setView({x:view.x+(view.w-w)/2,y:view.y+(view.h-h)/2,w,h});}
    $('zoom-in').addEventListener('click',()=>zoom(.8));$('zoom-out').addEventListener('click',()=>zoom(1.25));
    svg.addEventListener('wheel',event=>{event.preventDefault();zoom(event.deltaY>0?1.1:.9);},{passive:false});
    svg.addEventListener('pointerdown',event=>{if(event.target.closest('.asset-node'))return;drag={x:event.clientX,y:event.clientY,view:{...view}};svg.setPointerCapture(event.pointerId);});
    svg.addEventListener('pointermove',event=>{if(!drag)return;const rect=svg.getBoundingClientRect(),ratio=Math.max(view.w/rect.width,view.h/rect.height);setView({...drag.view,x:drag.view.x-(event.clientX-drag.x)*ratio,y:drag.view.y-(event.clientY-drag.y)*ratio});});
    for(const event of ['pointerup','pointercancel'])svg.addEventListener(event,()=>drag=null);
    $('motion-toggle').addEventListener('click',()=>{motion=!motion;updateMotion();});
    $('graph-scope').addEventListener('change',event=>{isAll=event.target.value==='all';focused=selected;drawMap();});
    $('map-fullscreen').addEventListener('click',()=>{$('graph').closest('.network-stage').classList.toggle('expanded-map');});
    document.addEventListener('keydown',event=>{if(event.key==='Escape')document.querySelector('.network-stage').classList.remove('expanded-map');});
    $('graph-search').addEventListener('input',event=>{
      const results=$('graph-results');results.replaceChildren();
      const term=event.target.value.trim().toLocaleLowerCase('pt-BR');if(!term)return;
      const matches=[...nodes.values()].filter(node=>(node.label+' '+node.setor+' '+node.tipo).toLocaleLowerCase('pt-BR').includes(term)).slice(0,8);
      if(!matches.length)results.append(html('p','','Nenhum ativo encontrado.'));
      for(const node of matches){const button=html('button','',node.label);button.type='button';button.addEventListener('click',()=>{focused=selected=node;isAll=false;$('graph-scope').value='focus';drawMap();showInspector(node);results.replaceChildren();$('graph-search').value='';});results.append(button);}
    });
    $('simulate-fix').addEventListener('click',async()=>{
      const button=$('simulate-fix'),result=$('simulation-result');const target=selected.id;
      button.disabled=true;result.hidden=false;result.textContent='Calculando cenário de correção…';
      try {
        const response=await fetch('/api/simular/'+target+'/',{headers:{Accept:'application/json'},credentials:'same-origin'});
        if(!response.ok)throw new Error('Sua conta não pode simular este cenário ou o ativo foi alterado.');
        const value=await response.json();
        if(selected.id!==target)return;
        result.textContent=`Corrigindo as ${value.correcoes} ocorrências ativas deste equipamento, o risco total passaria de ${fmt(value.antes)} para ${fmt(value.depois)} pontos (−${fmt(value.reducao)}). Nenhum dado foi alterado.`;
      } catch(error){result.textContent=error.message;}finally{button.disabled=false;}
    });
  } catch(error){status.textContent=error.message;$('graph-loading').hidden=true;}
}
startGraph();
