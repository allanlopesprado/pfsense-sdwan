# Comparativo de WAN no pfSense CE 2.9.2 isolado

Coleta completa. Estado do vínculo após a limpeza `present`.

Os pings foram originados pelo firewall, com endereço de origem fixo, para o gateway de cada WAN. As medições de RTT se referem ao gateway dentro do QEMU. O destino de aplicação, a experiência do cliente LAN e os tempos de produção têm ensaios próprios.

Na tabela de PF, a primeira medida indica a primeira amostra na rota esperada. A confirmação exige 3 amostras consecutivas observadas no mesmo caminho. A coluna de desvios posteriores registra quando essa sequência foi interrompida. A resolução é a cadência de coleta, cerca de um segundo mais os atrasos de execução. Um caminho já presente no primeiro poll não tem instante de transição medido.

Os tempos das tabelas partem do término do comando da fase. O CSV também registra o intervalo desde a solicitação. A ausência de evento dentro da janela é censura à direita.

## ICMP nos gateways

| Modo | Fase | Gateway | Enviados | Recebidos | Perdidos | Perda % | RTT mediana ms | RTT p95 ms | RTT máximo ms |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| native | baseline | wan1 | 6 | 6 | 0 | 0.000 | 7.286 | 17.799 | 17.799 |
| native | baseline | wan2 | 6 | 6 | 0 | 0.000 | 16.672 | 17.852 | 17.852 |
| native | wan1_down | wan1 | 29 | 0 | 29 | 100.000 | — | — | — |
| native | wan1_down | wan2 | 29 | 29 | 0 | 0.000 | 5.072 | 18.095 | 25.877 |
| native | both_down | wan1 | 7 | 0 | 7 | 100.000 | — | — | — |
| native | both_down | wan2 | 7 | 0 | 7 | 100.000 | — | — | — |
| native | wan2_restored | wan1 | 21 | 0 | 21 | 100.000 | — | — | — |
| native | wan2_restored | wan2 | 21 | 21 | 0 | 0.000 | 7.937 | 26.831 | 57.302 |
| native | wan1_restored | wan1 | 60 | 60 | 0 | 0.000 | 9.326 | 17.955 | 39.115 |
| native | wan1_restored | wan2 | 60 | 60 | 0 | 0.000 | 8.021 | 19.879 | 28.078 |
| sdwan | baseline | wan1 | 6 | 6 | 0 | 0.000 | 9.966 | 17.554 | 17.554 |
| sdwan | baseline | wan2 | 6 | 6 | 0 | 0.000 | 4.455 | 20.709 | 20.709 |
| sdwan | wan1_down | wan1 | 28 | 0 | 28 | 100.000 | — | — | — |
| sdwan | wan1_down | wan2 | 28 | 28 | 0 | 0.000 | 6.977 | 15.190 | 15.394 |
| sdwan | both_down | wan1 | 7 | 0 | 7 | 100.000 | — | — | — |
| sdwan | both_down | wan2 | 7 | 0 | 7 | 100.000 | — | — | — |
| sdwan | wan2_restored | wan1 | 19 | 0 | 19 | 100.000 | — | — | — |
| sdwan | wan2_restored | wan2 | 19 | 18 | 1 | 5.263 | 10.024 | 255.462 | 255.462 |
| sdwan | wan1_restored | wan1 | 63 | 63 | 0 | 0.000 | 9.997 | 33.908 | 91.328 |
| sdwan | wan1_restored | wan2 | 63 | 63 | 0 | 0.000 | 8.444 | 30.616 | 149.089 |

O p95 usa o posto mais próximo, e o cálculo de RTT usa somente respostas com valor de RTT.

| Modo | Fase | Gateway | Evento esperado | Primeiro ms | 3ª consecutiva ms | Estado |
| --- | --- | --- | --- | ---: | ---: | --- |
| native | wan1_down | wan1 | Ausência de resposta | 1975.209 | 5768.551 | stable |
| native | both_down | wan2 | Ausência de resposta | 1983.665 | 5845.355 | stable |
| native | wan2_restored | wan2 | Resposta | 486.993 | 4634.510 | stable |
| native | wan1_restored | wan1 | Resposta | 1161.635 | 2649.676 | stable |
| sdwan | wan1_down | wan1 | Ausência de resposta | 2133.088 | 6003.278 | stable |
| sdwan | both_down | wan2 | Ausência de resposta | 1953.078 | 5982.204 | stable |
| sdwan | wan2_restored | wan2 | Resposta | 431.619 | 7649.254 | stable |
| sdwan | wan1_restored | wan1 | Resposta | 284.120 | 2308.452 | stable |

## Regra carregada no PF

| Modo | Fase | Caminho esperado | Observações | Amostras no caminho | Primeiro ms | 3ª consecutiva ms | Desvios posteriores | Última rota | Estado |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| native | baseline | em0 | 6 | 6 | 389.890 | 2360.803 | 0 | em0 | stable |
| native | wan1_down | em2 | 29 | 18 | 21747.547 | 25509.870 | 0 | em2 | stable |
| native | both_down | block | 7 | 0 | — | — | — | em2 | right_censored |
| native | wan2_restored | em2 | 21 | 5 | 430.345 | 4895.784 | 16 | em2 | stable |
| native | wan1_restored | em0 | 60 | 14 | 51333.040 | 53357.140 | 0 | em0 | stable |
| sdwan | baseline | em0 | 6 | 6 | 351.722 | 2327.742 | 0 | em0 | stable |
| sdwan | wan1_down | em2 | 28 | 18 | 20797.576 | 24495.509 | 0 | em2 | stable |
| sdwan | both_down | block | 7 | 0 | — | — | — | em2 | right_censored |
| sdwan | wan2_restored | em2 | 19 | 11 | 604.229 | 6068.896 | 8 | em2 | stable |
| sdwan | wan1_restored | em0 | 63 | 4 | 61424.438 | 63486.707 | 0 | em0 | stable |

O CSV de PF inclui os outros caminhos observados, o próximo salto e a regra original do tracker. A saída bruta recortada preserva os eventos e amostras do console.
