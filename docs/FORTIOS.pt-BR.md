# Interoperabilidade com FortiGate em dois túneis IPsec

O cenário alvo é uma filial pfSense com duas WANs, dois túneis IPsec roteados e um FortiGate no outro extremo. Cada firewall administra o seu lado. A homologação de tráfego entre pfSense CE 2.9.1 e FortiOS continua pendente. Os testes do repositório exercitam componentes do pacote, do gerador de regras e do FreeBSD. O ensaio entre os dois produtos deve registrar as versões exatas e o fluxo de aplicação nos dois sentidos. [Integração implementada](INTEGRACAO.pt-BR.md) · [Laboratório](LAB.pt-BR.md)

## Capacidades e limites

| Tema | Implementação do projeto | Papel do FortiGate ou referência do Junos |
|---|---|---|
| Medição | O dpinger fornece RTT, desvio do RTT e perda por gateway. Os limites de SLA usam RTT e perda. Entre membros elegíveis, a política prefere menor custo configurado ou menor RTT. Um único membro permite acompanhar o SLA. | O FortiOS também permite medir jitter, empregar medições passivas e tomar decisões com suas próprias regras. O Junos RPM mede tempo de resposta, variação e perda. Os três métodos podem gerar números diferentes para o mesmo caminho. |
| Encaminhamento | No pfSense original, a decisão do pacote é informativa. No core experimental com ABI 1, um vínculo explícito pode selecionar o gateway de novos fluxos que correspondam às regras identificadas. O vínculo exige grupo dedicado, membros da mesma família e bloqueio adjacente com o mesmo alcance. | O operador configura zonas, rotas e regras SD-WAN no FortiGate. Escolhas de membro nos dois firewalls são independentes. |
| Dois túneis | Para ativar o vínculo, os dois gateways VTI precisam ter interfaces de transporte distintas e identificáveis. Dois filhos de uma única Fase 1 compartilham a negociação IKE e sua dependência de transporte. Duas VLANs ou placas virtuais diferentes ainda podem chegar ao mesmo circuito físico. | O FortiGate pode agrupar interfaces IPsec numa zona de overlay. No Junos, a rota seleciona uma interface segura `st0.x` e as políticas de segurança autorizam o tráfego. |
| Administração | A configuração de IKE, CARP, NAT, rotas e políticas remotas permanece com o operador. | Gestão centralizada no FortiManager, formação dinâmica de túneis ADVPN e seleção por aplicação ficam fora das capacidades implementadas pelo pacote. |

[Fortinet — membros e zonas](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/942095/sd-wan-zones) · [Fortinet — Performance SLA](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/584396/sd-wan-performance-sla) · [Juniper — VPN roteada](https://www.juniper.net/documentation/us/en/software/junos/vpn-ipsec/topics/topic-map/security-route-based-ipsec-vpns.html) · [Juniper — RPM](https://www.juniper.net/documentation/us/en/software/junos/flow-monitoring/network-mgmt/topics/topic-map/real-time-performance-monitoring.html)

## Onde usar `0.0.0.0/0`

| Local | Efeito e validação |
|---|---|
| Seletores do CHILD_SA | Na implementação VTI consultada, o pfSense acrescenta seletores amplos de IPv4 e IPv6. O FortiGate permite seletores locais e remotos amplos. Confira os seletores **negociados** em cada CHILD_SA. Os campos de rede da Fase 2 em modo VTI no pfSense definem os endereços internos do túnel. |
| Destino da regra da LAN | Uma origem específica da filial para destino IPv4 `any` pode encaminhar novos fluxos correspondentes pelo túnel. A ordem das regras deve preservar os destinos locais, de administração e outras VPNs. O pacote recusa vincular uma regra com origem e destino irrestritos. |
| Rota default da tabela do sistema | Altera o caminho geral da família IPv4, inclusive de serviços locais conforme suas rotas e vínculos. O pacote não instala essa rota e recusa usar o grupo de gateway definido como default do sistema. Num projeto de túnel integral, assegure em ambos os lados que os IPs públicos de IKE continuem alcançáveis pela WAN física durante queda e reconvergência. Avalie `::/0` separadamente. |

[Netgate — Fase 2](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/configure-p2.html) · [Código VTI do pfSense revisado](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/ipsec.inc#L2347-L2364) · [Fortinet — seletores de Fase 2](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/604285/phase-2-configuration) · [Fortinet — decisão de roteamento](https://docs.fortinet.com/document/fortigate/7.6.0/sd-wan-architecture-for-enterprise/768108/sd-wan-routing-logic)

## Perfil que os administradores precisam acordar

| Camada | Conferir em cada par pfSense–FortiGate |
|---|---|
| IKE | Para dois caminhos independentes, associar cada Fase 1 à WAN ou VIP de WAN correspondente. Combinar versão IKE, identidades local/remota, autenticação por PSK ou certificados e propostas compatíveis de cifra, integridade, PRF e grupo DH. Registrar DPD, temporizadores e comportamento de renegociação. |
| ESP | Associar cada Fase 2 à Fase 1 correta. Combinar propostas ESP, seletores e PFS/grupo DH. Registrar o tempo de vida de cada lado e verificar a renovação do CHILD_SA com tráfego. Configurar pares distintos de endereços internos e validar o endereço do vizinho em cada VTI. |
| NAT, retorno e HA | Definir onde ocorre o SNAT se houver saída para a Internet pelo concentrador. Para redes privadas roteadas, preservar a origem quando o desenho exigir e instalar retorno para o prefixo real. NAT-T transporta IPsec sobre UDP e resolve outra necessidade. No pfSense, NAT e `reply-to` por VTI dependem de um modo global de filtragem que afeta túneis por políticas. Em CARP, verificar o VIP de WAN na Fase 1 e a mesma ordem de atribuição das VTIs nos dois nós. |

[Netgate — Fase 1](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/configure-p1.html) · [Fortinet — Fase 1](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/790613/phase-1-configuration) · [Netgate — filtragem de VTI](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/routed-vti.html) · [Netgate — IPsec em HA](https://docs.netgate.com/pfsense/en/latest/highavailability/ipsec.html)

## Aceite do par de equipamentos

1. **Entrega por cada túnel.** Com os dois túneis negociados, teste A e B individualmente para o mesmo serviço remoto. Use alvos de monitoramento distintos e comparáveis, alcançados por dentro de cada túnel. Registre uma transação TCP completa no cliente e no destino, captura na VTI, encapsulamento ESP ou UDP/4500 na WAN correta, NAT efetivo, retorno e MTU com transferência de carga.
2. **Qualidade e assimetria.** Aplique perda ou latência controlada somente em A. Cronometre o primeiro fluxo novo útil em B e registre separadamente o destino das sessões já abertas. Verifique sessão, interface de retorno e contadores de ambos os firewalls. Na recuperação, o preferido saudável precisa sustentar a vantagem por 30 segundos no pacote. A fila de recarga e a próxima amostra acrescentam tempo.
3. **Perda dos dois túneis.** Mantenha as WANs físicas ativas e ambas as SAs indisponíveis. Gere tráfego exclusivo de teste para o prefixo protegido. Capture depois do NAT em ambas as WANs e confira os contadores do bloqueio e do destino. O critério é zero entrega do fluxo protegido em claro, inclusive durante recarga. Registre descartes da própria captura.
4. **Recuperação e rollback.** Repita com renovação de IKE e ESP, perda do nó CARP ativo e retorno do nó. Registre a primeira resposta útil, o nó MASTER por VIP e eventual interrupção de sessões. Desvincule a política, abra outra conexão e identifique a rota nativa efetivamente usada. Anexe versões, regras, capturas e horários sem credenciais ou chaves.
