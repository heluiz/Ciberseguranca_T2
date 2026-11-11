-- Executar somente no banco autorizado do projeto.
-- M:N, JOINs e autorralação das dependências.
SELECT a.hostname, v.cve, v.cvss, f.situacao
FROM inventory_asset a JOIN inventory_finding f ON f.asset_id = a.id
JOIN inventory_vulnerability v ON v.id = f.vulnerability_id
WHERE v.cvss >= 7 ORDER BY v.cvss DESC;

SELECT s.hostname AS depende, t.hostname AS destino, d.fracao
FROM inventory_dependency d
JOIN inventory_asset s ON s.id = d.source_id
JOIN inventory_asset t ON t.id = d.target_id;

-- CASE + GROUP BY + HAVING: setores com ao menos uma falha crítica não corrigida.
SELECT a.lotacao,
 COUNT(*) FILTER (WHERE f.situacao <> 3) AS nao_corrigidas,
 SUM(CASE WHEN v.cvss >= 9 AND f.situacao <> 3 THEN 1 ELSE 0 END) AS criticas
FROM inventory_asset a JOIN inventory_finding f ON f.asset_id = a.id
JOIN inventory_vulnerability v ON v.id = f.vulnerability_id
GROUP BY a.lotacao
HAVING SUM(CASE WHEN v.cvss >= 9 AND f.situacao <> 3 THEN 1 ELSE 0 END) > 0
ORDER BY criticas DESC;

-- Valores externos devem ser passados como parâmetros pelo ORM/driver.
EXPLAIN (ANALYZE, BUFFERS)
SELECT id, hostname FROM inventory_asset WHERE lower(hostname) = lower('SERVIDOR-01');
