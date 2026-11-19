# Integração do gerador de regras do pfSense

A ABI 1 permite que uma regra de entrada já aprovada pelo administrador escolha um próximo salto medido pelo pacote. O código público usado nesta versão identifica a base como `2.9.0-DEVELOPMENT`. A revisão é `9363ac5b8651a1c7a333180425ce7719070f95f9`. A compatibilidade com a imagem de um appliance CE 2.9.1 precisa de verificação própria. [Fonte usada para o gerador](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/filter.inc)

## Preparar a fonte no computador de build

Em um diretório de trabalho que contenha este projeto como `pfsense-sdwan`, use Python 3 e Git. Escolha um diretório novo para a saída.

```sh
git clone https://github.com/pfsense/pfsense.git pfsense-base
git -C pfsense-base checkout --detach 9363ac5b8651a1c7a333180425ce7719070f95f9
python3 pfsense-sdwan/tools/prepare-core.py --source pfsense-base --out sdwan-core-lab
git diff --no-index pfsense-base/src/etc/inc/filter.inc sdwan-core-lab/src/etc/inc/filter.inc
```

O último comando mostra a diferença e retorna 1 quando encontra alterações. O preparador verifica o SHA-256 do arquivo de origem, aplica o patch numa cópia e gera dois arquivos em `sdwan-core-lab/src/etc/inc`. Incorpore ambos na mesma revisão da árvore usada pelo seu processo de construção de imagem. Para outra base, compare também as implementações de inventário dos gateways, geração das regras, parser XML e recarga do filtro antes de portar a mudança. A restauração do snapshot do clone recupera sua imagem de referência. [Construção fora do firewall](https://docs.netgate.com/pfsense/en/latest/development/compile-software.html) · [Testes da imagem e rollback](../docs/LAB.pt-BR.md)

## Escopo do encaminhamento

O gerador consulta os próximos saltos que o pfSense calculou na recarga atual. Um vínculo identifica os trackers das regras aprovadas, a mesma família IP, o grupo dedicado, os membros e a revisão das condições de correspondência. A escolha de um gateway fica estável entre os trackers do mesmo vínculo durante uma geração completa. Sem amostra válida, a regra vinculada gera um bloqueio quando o filtro é recompilado. A prévia exige também um bloqueio nativo permanente de mesmo escopo logo abaixo da permissão, para os cenários em que o próprio pfSense omitir uma regra.

A política se aplica a conexões novas que alcancem a regra. Regras anteriores, NAT, conexões originadas pelo firewall e estados já criados requerem inspeção independente. A regra de bloqueio permanece sob administração do operador. O daemon solicita a recarga de forma assíncrona. Uma terminação abrupta pode deixar a última regra no kernel até a próxima recarga. O registro do pedido é distinto da confirmação pelo kernel. Confira os contadores do PF e as capturas de ida e volta. A interface **Forwarding** permite remover o vínculo para recuperar a decisão nativa do grupo.

A rota `0.0.0.0/0` do sistema e os endpoints IKE continuam sob administração nativa. Uma política pode selecionar uma WAN ou um VTI para destinos abrangentes desde que tenha origem delimitada, rotas de retorno compatíveis e as exceções locais de maior precedência. O piloto requer pelo menos dois caminhos e grupos separados para WAN e VTI. Para alta disponibilidade valide cada VIP CARP, a recuperação das SAs e a primeira transação útil. [Matriz de integração](../docs/INTEGRACAO.pt-BR.md)
