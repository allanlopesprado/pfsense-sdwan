# Integração com o encaminhamento e o IPsec do pfSense

O pacote recomenda um membro por política a partir dos dados do monitor de gateways do pfSense, o dpinger. Quem determina por onde passa uma conexão é o próprio pfSense, por meio das regras, rotas, estados e configurações de VPN. Uma troca da recomendação na tela e uma troca efetiva de caminho são eventos diferentes. A homologação em pfSense CE 2.9.1, inclusive contra um peer FortiOS, requer o ensaio de tráfego descrito abaixo.

## O que o processo acessa

| Componente | Operação do pacote |
|---|---|
| Gateways e monitoramento | Lê as entradas persistidas de gateways e interfaces e consulta o socket de estado do dpinger para os membros cadastrados. O alvo escolhido pelo administrador define o que a medição cobre. |
| Configuração | O editor salva membros, SLAs e políticas em `installedpackages/sdwan` pelo mecanismo nativo de configuração. Instalação e remoção usam o registro de pacotes do pfSense. |
| Medição e decisão | O serviço publica o resultado local em `/var/run/sdwan-observer.json`. O motor avalia a amostra e o SLA. Medições de RTT e variação de RTT correspondem à sondagem do gateway. |
| Encaminhamento e VPN | O ciclo de coleta e a gravação de políticas do pacote não chamam aplicadores de regras PF, NAT, rotas, FRR, CARP ou strongSwan. O daemon não cria nem encerra associações IPsec ou estados de usuários. |

Implementação examinada no [inventário e editor](../files/usr/local/pkg/sdwan.inc), [coletor](../files/usr/local/sbin/sdwand.php) e [motor de avaliação](../files/usr/local/pkg/sdwan_engine.inc).

## Matriz de topologias

| Topologia | O que o indicador permite concluir | O que conferir no firewall |
|---|---|---|
| Uma WAN | É possível acompanhar a saúde desse caminho. Com um único caminho disponível, uma pane o deixa sem alternativa. | Compare a resposta do próximo salto com uma conexão ao serviço real. Um modem pode responder durante uma queda da operadora. |
| Duas WANs, sem IPsec | Cada gateway pode ter uma medição. As WANs podem servir acesso direto à Internet. | Confira a saída de um cliente, a tradução de origem, o endereço visto no destino e o retorno por cada WAN. Teste entradas publicadas por NAT separadamente. |
| Dois VTIs em WANs distintas | É possível comparar os gateways de túneis atribuídos, presentes no inventário e monitorados. | Vincule cada sonda ao respectivo caminho. Confirme associação IKE e CHILD_SA, rota para o peer externo pela WAN, rota remota pela VTI e resposta do cliente remoto. |
| Dois VTIs na mesma WAN | Ambos podem ter RTT válido e ainda cair juntos. | Identifique qual Fase 1, circuito e enlace físico sustentam cada VTI. Separe a queda de um túnel da queda da WAN compartilhada. |
| WAN direta e VTI | Cada amostra descreve o próprio alvo. Um alvo público pode responder mesmo quando a rede privada está inacessível. | Compare caminhos que atendam ao mesmo destino e à mesma exigência de criptografia. Para prefixos privados protegidos, verifique que a perda de todos os túneis impede a saída em claro. |
| IPsec baseado em políticas, inclusive móvel | O IP público do peer pode responder com o túnel fora. Um túnel por seletores não fornece por si só um gateway VTI selecionável. | Confira os seletores da Fase 2, os contadores da associação e o serviço remoto. Em instalações mistas, preserve o processamento necessário aos túneis baseados em políticas. |
| HA com CARP | Cada nó observa seu próprio ambiente. O estado MASTER de um VIP identifica qual nó o possui. | Na Fase 1, selecione o VIP CARP da WAN onde a VPN termina. Atribua as interfaces VTI na mesma ordem em ambos os nós. Cronometre a renegociação com o peer e a primeira resposta da aplicação após a troca. |

Fontes da topologia e dos mecanismos nativos. [VTI e atribuição de interfaces](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/routed-vti.html) · [IPsec e multi-WAN](https://docs.netgate.com/pfsense/en/latest/multiwan/ipsec.html) · [IPsec e CARP, sincronização e DPD](https://docs.netgate.com/pfsense/en/latest/highavailability/ipsec.html) · [Diagnóstico multi-WAN](https://docs.netgate.com/pfsense/en/latest/troubleshooting/multi-wan.html)

## Pontos que mudam o resultado no tráfego real

**Rota padrão e seletores IPsec.** Na tabela do sistema, `0.0.0.0/0` é a rota IPv4 usada quando falta uma mais específica. Na negociação IPsec, um seletor `0.0.0.0/0` expressa a cobertura de endereços e depende de acordo entre os peers. O pacote não instala nenhuma dessas configurações. Em um túnel de saída padrão, verifique a rota até o endereço público do próprio peer, a rota do destino interno e o caminho de volta. Com duas WANs para o mesmo IP de peer, verifique a saída de IKE de cada conexão em captura. O gerador nativo condiciona a criação da rota específica, inclusive no caso de peers duplicados. Para dual stack, repita a validação com `::/0`. [Seletores IKEv2 na RFC 7296, seção 2.9](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.9) · [VTI e rota padrão automática](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/routed-vti.html) · [Rotas nativas para o peer](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/ipsec.inc#L2045-L2096)

**Filtros, NAT e estados.** No modo IPsec padrão, o tráfego VTI passa pela aba IPsec e pode aparecer em `ipsecX` e `enc0`. Isso influencia estados vinculados à interface. Para NAT e `reply-to` na interface VTI atribuída, a Netgate documenta o modo de filtragem nas interfaces atribuídas. É uma configuração global que bloqueia tráfego em modo túnel e é incompatível com IPsec móvel. Em ambiente misto, examine a alternativa documentada de estados flutuantes em regras específicas para as VTIs. Para NAT em WAN, confirme ainda se o IP de origem traduzido corresponde à saída e, em HA, ao VIP previsto. [Filtragem VTI](https://docs.netgate.com/pfsense/en/latest/config/advanced-firewall-nat.html#ipsec-vti-filtering) · [NAT multi-WAN](https://docs.netgate.com/pfsense/en/latest/multiwan/nat.html)

**Retorno e origem da conexão.** Em PF, `route-to` afeta o sentido indicado pela regra e `reply-to` afeta a resposta de uma conexão com estado. Uma regra de entrada na LAN com gateway escolhido pode alcançar também destinos de uma VPN se as exceções estiverem abaixo dela. Já conexões iniciadas pelo firewall, como consultas DNS, seguem a tabela de rotas e as condições de vinculação do serviço. Teste uma conexão iniciada na LAN, outra iniciada de fora para um serviço publicado e uma terceira iniciada pelo firewall. [Opções de roteamento em pf.conf(5)](https://man.freebsd.org/cgi/man.cgi?query=pf.conf&sektion=5) · [Ordem das regras e comportamento com gateway indisponível](https://docs.netgate.com/pfsense/en/latest/multiwan/policy-route.html) · [Serviços locais e multi-WAN](https://docs.netgate.com/pfsense/en/latest/multiwan/considerations.html)

## Ensaio de aceitação

1. Registre versões, topologia, endereços dos alvos, mapeamento VTI–WAN, rotas IPv4/IPv6, regras PF/NAT e associações IPsec. Guarde uma transação real com resposta como referência.
2. No clone, execute os mesmos fluxos antes e depois de salvar uma política. Registre interface de ida, interface de volta, tradução e resultado no cliente. Para VTI, capture o fluxo interno na interface de túnel e o encapsulamento na WAN. Inclua carga suficiente para exercitar MTU, por exemplo uma transferência HTTPS.
3. Em testes separados, indisponibilize apenas o alvo, apenas o túnel e apenas uma WAN. Teste depois a falha dos dois caminhos. Registre recomendação, caminho efetivo, recuperação de sessões preexistentes e tempo para uma nova sessão. Confirme por captura que um destino que exige VPN permanece protegido mesmo sem túnel.
4. Em HA, repita com perda do nó ativo e em seu retorno. Anote MASTER por VIP, tempo até o novo CHILD_SA e tempo até a aplicação voltar a responder. A recuperação pode depender de DPD, da iniciativa do peer e dos estados nativos.
5. Contra FortiOS, registre a versão e as propostas, IDs, seletores e rotas nas duas pontas. Teste os dois sentidos, rekey, falha e recuperação. O aceite exige tráfego de aplicação e retorno observado na topologia ensaiada. [Roteiro de laboratório](LAB.pt-BR.md)

O FortiOS combina medições ativas ou passivas com regras que dirigem tráfego. O PAN-OS permite ponderar a sensibilidade a perda, latência e jitter por perfil. Esses produtos servem de referência para comparar métricas, comportamento durante falhas e recuperação. O observador deste projeto usa a telemetria local do dpinger e publica uma recomendação. Asserções de interoperabilidade e tempos de convergência dependem de resultados de laboratório identificados por versão e topologia. [FortiOS Performance SLA](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/584396/sd-wan-performance-sla) · [FortiOS SD-WAN rules](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/683285/sd-wan-rules) · [PAN-OS Path Quality Profile](https://docs.paloaltonetworks.com/ngfw/help/11-1/objects/objects-sd-wan-link-management/objects-sd-wan-link-management-path-quality-profile)
