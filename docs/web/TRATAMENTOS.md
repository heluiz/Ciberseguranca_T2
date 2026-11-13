# Datas e histórico de detecção/correção

Cada ocorrência (vulnerabilidade em um ativo) tem `detected_at` e `corrected_at` no PostgreSQL. A vulnerabilidade compartilhada não tem uma única data de correção: cada equipamento pode ser tratado em um momento diferente.

- O formulário sugere a data atual para uma nova detecção. O usuário pode informar uma data anterior ou limpar o campo quando ela for desconhecida. Na API, omitir a detecção no cadastro usa a hora atual; enviar `null` registra data desconhecida.
- Ao mudar para Corrigida, o sistema registra a hora atual quando não há uma data de correção informada. O usuário pode informar a data histórica real.
- Não são aceitas datas futuras nem correção anterior à detecção. Há restrições adicionais no banco para correção vinculada à situação Corrigida e para ordem cronológica.
- Datas são armazenadas com fuso (UTC no banco), apresentadas no horário de Brasília e registradas com precisão de segundos.
- Reabrir uma ocorrência remove sua data de correção atual e preserva o fechamento anterior no histórico. Uma nova correção gera outro evento.
- O histórico guarda instante da operação, conta responsável quando disponível, IDs do ativo/falha, situações e datas antes/depois. O instante da operação é automático e distinto da data histórica informada pelo usuário.
- Trocar o ativo ou a vulnerabilidade de uma ocorrência existente é recusado: deve ser criada outra ocorrência, preservando a identidade do histórico.
- Exclusão de ocorrência, ativo ou vulnerabilidade preserva os eventos, com IDs de referência; a relação com a ocorrência excluída fica nula. Exclusão da conta pode deixar o ator indisponível, conforme a política de usuários existente.
- Registros antigos e importação JSON não recebem datas fictícias. A importação gera evento com datas desconhecidas; registros que já existiam antes da migração começam a ter histórico em sua próxima alteração.

As datas aparecem na listagem de tratamentos, na ficha do ativo, nos detalhes do mapa e na linha do tempo do tratamento. A auditoria global mostra os últimos 100 eventos de tratamento; a linha do tempo individual mostra os últimos 200. O CSV administrativo exporta o histórico completo, com IDs e timestamps ISO 8601 UTC, sem nomes pessoais.

A exportação JSON compatível com a CLI não contém essas datas nem o histórico. Use backup PostgreSQL completo para restauração; o CSV serve para análise de auditoria. O histórico da aplicação não é imutável contra o proprietário do banco.
