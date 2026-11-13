-- Consultas de estudo sobre o banco do SENTINEL (somente leitura).
-- Executar no banco do projeto, por exemplo:
--   docker compose -f compose.servidor.yaml exec -T db psql -U sentinel_owner -d sentinel < docs/web/consultas.sql
-- Na aplicação, valores vindos do usuário nunca são colados no SQL: o Django
-- os envia como parâmetros da consulta.

-- 1. INNER JOIN na relação N:N (ativo <-> vulnerabilidade, pela tabela de tratamentos).
SELECT a.hostname, v.cve, v.cvss, f.situacao
FROM inventory_asset a
JOIN inventory_finding f ON f.asset_id = a.id
JOIN inventory_vulnerability v ON v.id = f.vulnerability_id
WHERE v.cvss >= 7
ORDER BY v.cvss DESC, a.hostname;

-- 2. LEFT JOIN: vulnerabilidades do catálogo que não estão vinculadas a nenhum ativo.
SELECT v.id, v.cve, v.cvss
FROM inventory_vulnerability v
LEFT JOIN inventory_finding f ON f.vulnerability_id = v.id
WHERE f.id IS NULL
ORDER BY v.id;

-- 3. LEFT JOIN: ativos sem nenhuma vulnerabilidade vinculada.
SELECT a.id, a.hostname
FROM inventory_asset a
LEFT JOIN inventory_finding f ON f.asset_id = a.id
WHERE f.id IS NULL
ORDER BY a.hostname;

-- 4. Autorrelacionamento: a mesma tabela de ativos entra duas vezes (quem herda e de quem).
SELECT s.hostname AS herda_risco, t.hostname AS depende_de, d.fracao
FROM inventory_dependency d
JOIN inventory_asset s ON s.id = d.source_id
JOIN inventory_asset t ON t.id = d.target_id
ORDER BY s.hostname, t.hostname;

-- 5. Agregações por setor: COUNT, AVG, MAX e SUM com GROUP BY (só falhas não corrigidas).
SELECT a.lotacao,
       COUNT(DISTINCT a.id) AS ativos,
       COUNT(f.id) AS falhas_abertas,
       ROUND(AVG(v.cvss), 2) AS cvss_medio,
       MAX(v.cvss) AS cvss_maximo,
       SUM(v.cvss) AS soma_cvss
FROM inventory_asset a
LEFT JOIN inventory_finding f ON f.asset_id = a.id AND f.situacao <> 3
LEFT JOIN inventory_vulnerability v ON v.id = f.vulnerability_id
GROUP BY a.lotacao
ORDER BY falhas_abertas DESC, a.lotacao;

-- 6. CASE + GROUP BY + HAVING: setores com ao menos uma falha crítica não corrigida.
SELECT a.lotacao,
       COUNT(*) FILTER (WHERE f.situacao <> 3) AS nao_corrigidas,
       SUM(CASE WHEN v.cvss >= 9 AND f.situacao <> 3 THEN 1 ELSE 0 END) AS criticas
FROM inventory_asset a
JOIN inventory_finding f ON f.asset_id = a.id
JOIN inventory_vulnerability v ON v.id = f.vulnerability_id
GROUP BY a.lotacao
HAVING SUM(CASE WHEN v.cvss >= 9 AND f.situacao <> 3 THEN 1 ELSE 0 END) > 0
ORDER BY criticas DESC, a.lotacao;

-- 7. Soma de CVSS por ativo (o "M v" do modelo, antes do fator do tipo e da herança).
--    Compare com a coluna "Soma CVSS" da tela Análise de risco: falhas corrigidas não contam.
SELECT a.hostname, COALESCE(SUM(v.cvss), 0) AS soma_cvss
FROM inventory_asset a
LEFT JOIN inventory_finding f ON f.asset_id = a.id AND f.situacao <> 3
LEFT JOIN inventory_vulnerability v ON v.id = f.vulnerability_id
GROUP BY a.id, a.hostname
ORDER BY soma_cvss DESC, a.hostname
LIMIT 10;

-- 8. Plano de execução da busca por hostname. Existe um índice único sobre
--    lower(hostname). Com poucas linhas o PostgreSQL costuma preferir ler a
--    tabela inteira (Seq Scan), porque é mais barato do que consultar o índice.
EXPLAIN (ANALYZE, BUFFERS)
SELECT id, hostname FROM inventory_asset WHERE lower(hostname) = lower('SERVIDOR-01');

-- 9. A mesma busca com a varredura sequencial desestimulada: o plano passa a
--    usar o índice (Index Scan). O ajuste vale só dentro desta transação.
BEGIN;
SET LOCAL enable_seqscan = off;
EXPLAIN (ANALYZE, BUFFERS)
SELECT id, hostname FROM inventory_asset WHERE lower(hostname) = lower('SERVIDOR-01');
ROLLBACK;

-- 10. Busca por um campo sem índice: só resta percorrer a tabela.
EXPLAIN (ANALYZE, BUFFERS)
SELECT id, hostname FROM inventory_asset WHERE custodiante = 'Suporte';
