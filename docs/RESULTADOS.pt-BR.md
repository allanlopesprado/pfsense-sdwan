# Resultados do laboratório de SD-WAN

A versão 0.3.0 do pacote contém a WebGUI, o widget, o serviço de medição e o módulo de seleção. O adaptador do filtro é entregue separadamente para uma imagem de laboratório. A distribuição `pfSense-pkg-SDWAN-0.3.0.pkg` ocupa 25.004 bytes e tem SHA-256 `6552b2fcbc97de2be53a5c926c7f1539d06514902a42b1eb87f9b0a2aa595476`. [Binário da revisão fixa](https://github.com/allanlopesprado/pfsense-sdwan/blob/fe20885be522fb680e2c607bb4c298fbfdb76490/dist/pfSense-pkg-SDWAN-0.3.0.pkg)

| Ensaio | Observação |
|---|---|
| Atualização e reversão | A VM de CI baixou o arquivo com o comando do README. Em uma raiz isolada, o banco do pkg passou de 0.2.0 para 0.3.0 e voltou para 0.2.0. Um arquivo truncado foi rejeitado. A raiz usou metadados de ABI do alvo. Os hooks e o registro da WebGUI são exercitados em testes separados. |
| Telemetria e compilação | O daemon recebeu amostras controladas no formato do dpinger por sockets Unix. O gerador da fonte do pfSense, com o adaptador, produziu regras para A, B e nenhum caminho. O mesmo vínculo preservou uma decisão entre dois trackers na mesma recarga. Snapshot vencido, exclusão do grupo ou remoção do provider resultaram em bloqueio na compilação. |
| Tráfego encaminhado | O PF do FreeBSD carregou as regras produzidas na etapa anterior. Uma aplicação TCP na outra ponta respondeu com o endereço de origem visto após NAT. Ao mudar a seleção, a sessão existente usou A e uma nova sessão usou B. Com os dois caminhos inelegíveis, a tentativa abrangida foi bloqueada enquanto um destino de controle continuou pela rota padrão. |
| CARP | Duas instâncias em VNET compartilharam um VIP. Depois da perda da interface do MASTER, um cliente existente e outro recém-conectado alcançaram o VIP pelo novo MASTER. A preferência original retornou após a recuperação. O tempo inclui o intervalo das sondagens e depende da topologia. |
| VTI sem SA | Com rota pelo túnel e sem associação de segurança, o contador IPsec de ausência de SA aumentou. O contador de ICMP em claro no peer permaneceu estável. Os controles antes e depois do ensaio alcançaram o destino fora do túnel. |
| VTI com ESP | O peer e o firewall receberam ESP nas respectivas interfaces físicas e o destino devolveu três respostas através do túnel. Depois da retirada de **uma única SA de saída**, o fluxo parou, o kernel registrou ausência de SA e os contadores do ICMP protegido em claro permaneceram nos valores do controle inicial. As duas pontas usaram SAs manuais. |

O teste de VTI e o teste de failover CARP usam topologias diferentes. O teste de CARP mede a disponibilidade do VIP. Recuperar uma sessão de aplicação através de um túnel após troca de MASTER é outro critério. [Execução do teste com ESP e bloqueio após remoção da SA](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44459464879/job/135342599341)

A VM executou FreeBSD 15. A fonte pública do gerador do pfSense usada nos ensaios se identifica como `2.9.0-DEVELOPMENT`, revisão `9363ac5b8651a1c7a333180425ce7719070f95f9`. O daemon usou amostras controladas e o tráfego TCP atravessou interfaces reais de VNET. A captura em um appliance com dpinger medindo degradação física continua necessária para determinar o tempo de convergência de ponta a ponta. [Execução com regras do pfSense e tráfego no FreeBSD](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44459108859)

## Widget e WebGUI da versão 0.4.0

O pacote 0.4.0 disponibilizado em `main` ocupa **28.924 bytes** e tem SHA-256 `67251efd7fd8841fb26b65dbfead379867ddf5274adfe456766d3db182d8c7d8`. Duas construções independentes produziram os mesmos bytes. O instalador verifica esse valor antes de chamar o gerenciador de pacotes. [Arquivo fixado no instalador](https://github.com/allanlopesprado/pfsense-sdwan/blob/c0372cadc2ce6be6afa7c01c0db85bba23bc26d6/dist/pfSense-pkg-SDWAN-0.4.0.pkg)

No Chromium, o widget usou o CSS dos temas claro e escuro do pfSense a 360 e 640 px. Nas quatro combinações, os dados de teste e os identificadores longos couberam sem rolagem horizontal. O foco do teclado permaneceu na política selecionada após a atualização AJAX. O contraste mínimo medido nos valores e legendas foi de 12:1 no tema claro e 10,05:1 no escuro. Os formulários e links foram testados com a navegação, os filtros de logs, a verificação de privilégios e a proteção CSRF da fonte de referência. [Amostras visuais e métricas](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44461547088/artifacts/14500182251)

## Eventos em System Logs

O teste extraiu o emissor do pacote 0.4.0 e o executou com o `syslogd` do FreeBSD 15.1. O leitor usado pela página General reconheceu cinco eventos distintos do processo `sdwan` no formato RFC 3164 e cinco no RFC 5424 com a severidade padrão. Com o limite ajustado para `warning`, dois eventos ficaram visíveis. Uma sequência de 25 falhas idênticas gerou um único erro. A mensagem do processo de controle `dpinger` seguiu para o log de gateways. A prova exercita o emissor, as regras de roteamento de logs e o parser reais. A visita à página em um appliance CE 2.9.1 permanece na matriz de homologação. [Log completo da execução](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44462039273/job/135351197785)

## Correção do transporte de logs na versão 0.4.1

Uma repetição do teste da versão 0.4.0 registrou apenas o primeiro evento de uma sequência. O processo do pacote abria e fechava uma conexão local por mensagem. No FreeBSD, ao desconectar um emissor de datagramas Unix, o kernel pode descartar mensagens pendentes se a fila compartilhada do receptor já tiver dados. A versão 0.4.1 mantém uma conexão no serviço dedicado e restaura a identificação do PHP entre chamadas. [Comportamento no kernel do FreeBSD 15.1](https://github.com/freebsd/freebsd-src/blob/releng/15.1/sys/kern/uipc_usrreq.c#L3230-L3266)

O teste da 0.4.1 compara nove combinações de formato, severidade e ciclo de execução. Na terceira rodada, pausa o syslogd antes do primeiro evento, envia a sequência uma única vez e retoma a leitura. Verifica cada mensagem recebida, os eventos que o log geral deve exibir e a identificação de uma mensagem posterior do PHP. O pacote mede **29.140 bytes** e produziu o mesmo SHA-256 em duas construções independentes. [Arquivo fixado no instalador](https://github.com/allanlopesprado/pfsense-sdwan/blob/f3f669217300c2ebd126119cb87bfcf34ef3d94a/dist/pfSense-pkg-SDWAN-0.4.1.pkg)

As nove combinações passaram no FreeBSD 15.1. Em cada rodada, o leitor da página General exibiu cinco eventos com a severidade padrão nos dois formatos e dois com o limite em `warning`. O mesmo job verificou atualização das três versões anteriores e reversão do pacote, com hooks desativados em raízes isoladas. [Resultados da 0.4.1 no FreeBSD](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44463868187/job/135357178008) · [Testes de interface e temas](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44463868187/job/135356837862)

## Negociação IKEv2 com dois caminhos

Dois processos strongSwan do Ubuntu 24.04 negociaram duas IKE_SAs e dois CHILD_SAs independentes. O teste observou ESP nas duas direções de cada enlace e contadores de dados nas duas pontas. Durante a renovação do CHILD_SA e depois da IKE_SA do caminho A, o caminho B manteve seus SPIs e continuou transportando dados. Ao remover a associação A, as sondagens protegidas desse caminho falharam nos dois sentidos e os contadores de tráfego em claro permaneceram estáveis nos dois enlaces. [Execução com strongSwan 5.9.13](https://github.com/allanlopesprado/pfsense-sdwan/actions/runs/44460493186/job/135345795505)

## Aceite em equipamento

No CE 2.9.1, a atualização do 0.4.2 para o 0.4.3 executou os hooks reais. A verificação no equipamento confirmou integridade, registro de pacote e serviço, amostra atual e eventos no leitor nativo do log. A configuração do SD-WAN e as regras PF e NAT apresentaram os mesmos valores antes e depois. [Versão 0.4.3](https://github.com/allanlopesprado/pfsense-sdwan/releases/tag/v0.4.3)

Permanecem pendentes a negociação e o rekey IKEv2 com FortiOS, o retorno simétrico nas duas WANs e a recuperação conjunta de CARP, estados e IPsec entre dois appliances usando a imagem CE 2.9.1. A entrega experimental cobre seleção de caminho por regra de entrada. A decisão de rota padrão do próprio firewall, a distribuição por catálogo e os recursos específicos do FortiOS têm critérios próprios. [Matriz de interoperabilidade](FORTIOS.pt-BR.md) · [Procedimento de homologação](LAB.pt-BR.md)
