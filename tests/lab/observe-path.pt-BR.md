# Conferir ida e volta de um cliente no clone

Use este ensaio quando souber qual interface LAN recebe o fluxo e qual interface deve encaminhá-lo. Há dois pontos de captura no mesmo firewall. Um cliente de laboratório envia um ping IPv4 para um alvo dedicado que responde a ICMP. Para conferir outro circuito, repita o ensaio selecionando sua interface. Para VTI, use a interface que transporta o fluxo interno.

**No shell do clone**, execute o coletor deste repositório. Os endereços abaixo são de documentação. Substitua as duas interfaces e os três endereços. Os argumentos representam, nesta ordem, interface LAN, interface de saída esperada, IP do cliente na LAN, IP desse cliente visto na saída após o NAT, IP do alvo e duração em segundos. Quando não houver NAT, repita o IP do cliente no quarto argumento. Para uma VLAN, use a interface lógica já atribuída.

```sh
sh tests/lab/observe-path.sh vtnet1 vtnet2 192.0.2.10 198.51.100.20 203.0.113.50 20
```

**No cliente**, assim que o coletor exibir `Captures ready`, inicie um novo processo e aguarde a conclusão. Comece sem outro ping em andamento entre os mesmos endereços. Reserve um alvo exclusivo durante a janela quando vários clientes compartilham o IP traduzido.

```sh
ping -c 3 203.0.113.50
```

O coletor usa o tipo, o sentido e a sequência de cada echo para correlacionar os quatro eventos. O ID pode mudar entre LAN e saída por efeito do NAT. O resultado esperado para três respostas, sem perda, é:

```json
{"result":"round_trip_observed","window_s":20,"lan_requests":3,"path_requests":3,"path_replies":3,"lan_replies":3,"complete_sequences":3}
```

| Resultado | Leitura |
|---|---|
| `round_trip_observed` | Cada sequência observada teve solicitação e resposta nas duas interfaces. Compare também a quantidade com os pings enviados e recebidos no cliente. |
| `incomplete` | Ao menos uma sequência ficou sem um dos quatro eventos. Os contadores mostram até qual ponto foi possível seguir o tráfego. Confirme IP traduzido, interface, retorno e estado da conexão. |
| `no_samples` | A janela terminou sem pacotes entregues pelos filtros. Confira captura simultânea, alvo e interfaces. |
| `multiple_flows` | Uma mesma interface apresentou mais de um identificador ICMP. Repita o ensaio com um único ping e o alvo dedicado. |

O código de saída é `0` para ida e volta observadas, `1` para os outros três resultados e `2` para erro de captura, perdas no kernel, decodificação incompleta ou parâmetros inválidos. A saída JSON contém somente contagens. Os arquivos temporários privados guardam os identificadores, sequências e diagnósticos do tcpdump durante o ensaio. O processo os remove ao terminar. Pacotes brutos, configuração e material IPsec não compõem o relatório.

Execute uma janela antes da falha e outra depois da troca com um novo processo de ping. Registre separadamente o resultado da aplicação e o caminho alternativo. A observação de ICMP exige confirmação adicional para fluxos TCP, UDP e IPv6, retorno por outro firewall, sigilo no túnel e cobertura dos seletores. Para validar contenção em IPsec, observe também as WANs candidatas procurando o destino privado em claro, inclusive após NAT, e confirme tráfego encapsulado, contadores do túnel e recebimento na ponta remota. As contagens deste coletor, isoladamente, não demonstram contenção nem provam entrega a uma aplicação. [Diagnóstico de multi-WAN da Netgate](https://docs.netgate.com/pfsense/en/latest/troubleshooting/multi-wan.html)
