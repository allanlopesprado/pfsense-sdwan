# SD-WAN A/B benchmark

Convergence requires three consecutive successful attempts. Times are from the
actual fault or repair event to the first reply in that streak and to confirmation
of the entire streak. A missing streak is reported with its observation window.
Failures include all recorded statuses other than OK. Response and connection
latencies include successful requests only. P95 uses the nearest rank.
A boundary-crossing request is attributed to the phase where it started.

## ERP recovery by run

| Run | Scenario | Mode | WAN2 during fault | Service after repair | WAN1 after repair | Last 3 completed before repair succeeded |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | erp_wan1 | native | not observed in 12.009 s (47 completed attempts) | 0.234 / 0.734 s | 0.234 / 0.734 s | no |
| 2 | erp_wan1 | sdwan | 3.492 / 3.993 s | 0.233 / 0.734 s | 30.983 / 31.483 s | yes |
| 3 | erp_wan1 | sdwan | 3.492 / 3.993 s | 0.234 / 0.734 s | 30.983 / 31.483 s | yes |
| 4 | erp_wan1 | native | not observed in 12.009 s (47 completed attempts) | 0.233 / 0.733 s | 0.233 / 0.733 s | no |
| 5 | erp_wan1 | native | not observed in 12.009 s (47 completed attempts) | 0.233 / 0.733 s | 0.233 / 0.733 s | no |
| 6 | erp_wan1 | sdwan | 3.492 / 3.992 s | 0.233 / 0.733 s | 30.983 / 31.483 s | yes |

## Pooled traffic measurements

| Scenario | Mode | Runs | Phase | Flow | OK / total | Failed % | Timeout | Response ms P50 / P95 / max (n) | TCP connect ms P50 / P95 / max (n) | Successful replies by source | Crossed boundary |
| --- | --- | ---: | --- | --- | ---: | ---: | ---: | --- | --- | --- | ---: |
| erp_wan1 | native | 3 | baseline | backup | 63 / 63 | 0.00% | 0 | 1.579 / 2.165 / 3.247 (63) | 0.207 / 0.538 / 0.777 (63) | 198.51.100.1 × 63 | 0 |
| erp_wan1 | native | 3 | baseline | dns | 63 / 63 | 0.00% | 0 | 0.479 / 0.695 / 0.910 (63) | — (0) | — | 0 |
| erp_wan1 | native | 3 | baseline | erp | 63 / 63 | 0.00% | 0 | 1.607 / 1.961 / 3.781 (63) | 0.189 / 0.422 / 0.538 (63) | 198.51.100.1 × 63 | 0 |
| erp_wan1 | native | 3 | baseline | erp_persistent | 63 / 63 | 0.00% | 0 | 0.254 / 0.751 / 3.444 (63) | 0.313 / 0.346 / 0.346 (3) | 198.51.100.1 × 63 | 0 |
| erp_wan1 | native | 3 | fault | backup | 144 / 144 | 0.00% | 0 | 1.560 / 1.798 / 2.069 (144) | 0.182 / 0.343 / 0.833 (144) | 198.51.100.1 × 144 | 0 |
| erp_wan1 | native | 3 | fault | dns | 144 / 144 | 0.00% | 0 | 0.499 / 0.819 / 1.082 (144) | — (0) | — | 0 |
| erp_wan1 | native | 3 | fault | erp | 0 / 144 | 100.00% | 144 | — (0) | — (0) | — | 3 |
| erp_wan1 | native | 3 | fault | erp_persistent | 0 / 144 | 100.00% | 144 | — (0) | — (0) | — | 3 |
| erp_wan1 | native | 3 | recovery | backup | 453 / 453 | 0.00% | 0 | 1.631 / 1.977 / 4.172 (453) | 0.212 / 0.472 / 2.866 (453) | 198.51.100.1 × 453 | 0 |
| erp_wan1 | native | 3 | recovery | dns | 453 / 453 | 0.00% | 0 | 0.499 / 0.740 / 2.900 (453) | — (0) | — | 0 |
| erp_wan1 | native | 3 | recovery | erp | 453 / 453 | 0.00% | 0 | 1.642 / 2.020 / 4.314 (453) | 0.214 / 0.435 / 2.972 (453) | 198.51.100.1 × 453 | 0 |
| erp_wan1 | native | 3 | recovery | erp_persistent | 390 / 453 | 13.91% | 63 | 0.247 / 0.466 / 96.848 (390) | — (0) | 198.51.100.1 × 390 | 0 |
| erp_wan1 | sdwan | 3 | baseline | backup | 63 / 63 | 0.00% | 0 | 1.702 / 1.909 / 2.056 (63) | 0.260 / 0.441 / 0.536 (63) | 198.51.100.1 × 63 | 0 |
| erp_wan1 | sdwan | 3 | baseline | dns | 63 / 63 | 0.00% | 0 | 0.541 / 0.825 / 0.901 (63) | — (0) | — | 0 |
| erp_wan1 | sdwan | 3 | baseline | erp | 63 / 63 | 0.00% | 0 | 1.670 / 1.946 / 2.007 (63) | 0.238 / 0.443 / 0.579 (63) | 198.51.100.1 × 63 | 0 |
| erp_wan1 | sdwan | 3 | baseline | erp_persistent | 63 / 63 | 0.00% | 0 | 0.297 / 0.703 / 1.650 (63) | 0.162 / 0.391 / 0.391 (3) | 198.51.100.1 × 63 | 0 |
| erp_wan1 | sdwan | 3 | fault | backup | 144 / 144 | 0.00% | 0 | 1.604 / 1.977 / 2.240 (144) | 0.198 / 0.376 / 0.820 (144) | 198.51.100.1 × 144 | 0 |
| erp_wan1 | sdwan | 3 | fault | dns | 144 / 144 | 0.00% | 0 | 0.520 / 0.758 / 1.204 (144) | — (0) | — | 0 |
| erp_wan1 | sdwan | 3 | fault | erp | 105 / 144 | 27.08% | 39 | 1.674 / 1.985 / 2.255 (105) | 0.209 / 0.398 / 0.495 (105) | 203.0.113.1 × 105 | 0 |
| erp_wan1 | sdwan | 3 | fault | erp_persistent | 0 / 144 | 100.00% | 144 | — (0) | — (0) | — | 3 |
| erp_wan1 | sdwan | 3 | recovery | backup | 453 / 453 | 0.00% | 0 | 1.464 / 1.926 / 4.849 (453) | 0.177 / 0.447 / 3.193 (453) | 198.51.100.1 × 453 | 0 |
| erp_wan1 | sdwan | 3 | recovery | dns | 453 / 453 | 0.00% | 0 | 0.442 / 0.700 / 3.255 (453) | — (0) | — | 0 |
| erp_wan1 | sdwan | 3 | recovery | erp | 453 / 453 | 0.00% | 0 | 1.478 / 1.865 / 4.869 (453) | 0.193 / 0.405 / 3.427 (453) | 198.51.100.1 × 84 — 203.0.113.1 × 369 | 0 |
| erp_wan1 | sdwan | 3 | recovery | erp_persistent | 388 / 453 | 14.35% | 65 | 0.222 / 0.439 / 119.119 (388) | — (0) | 198.51.100.1 × 388 | 0 |

## Run 1 · native · erp_wan1

Fault window 12.009 s. Recovery window 37.756 s.

| Phase | Flow | OK / total | Failed % | Timeout | Response ms P50 / P95 / max (n) | TCP connect ms P50 / P95 / max (n) | Successful replies by source | Crossed boundary |
| --- | --- | ---: | ---: | ---: | --- | --- | --- | ---: |
| baseline | backup | 21 / 21 | 0.00% | 0 | 1.702 / 2.581 / 3.247 (21) | 0.236 / 0.724 / 0.777 (21) | 198.51.100.1 × 21 | 0 |
| fault | backup | 48 / 48 | 0.00% | 0 | 1.581 / 1.778 / 1.815 (48) | 0.185 / 0.350 / 0.833 (48) | 198.51.100.1 × 48 | 0 |
| recovery | backup | 151 / 151 | 0.00% | 0 | 1.736 / 2.045 / 4.172 (151) | 0.243 / 0.516 / 2.866 (151) | 198.51.100.1 × 151 | 0 |
| baseline | dns | 21 / 21 | 0.00% | 0 | 0.588 / 0.844 / 0.910 (21) | — (0) | — | 0 |
| fault | dns | 48 / 48 | 0.00% | 0 | 0.547 / 0.767 / 1.082 (48) | — (0) | — | 0 |
| recovery | dns | 151 / 151 | 0.00% | 0 | 0.562 / 0.814 / 2.900 (151) | — (0) | — | 0 |
| baseline | erp | 21 / 21 | 0.00% | 0 | 1.795 / 2.469 / 3.781 (21) | 0.279 / 0.447 / 0.538 (21) | 198.51.100.1 × 21 | 0 |
| fault | erp | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp | 151 / 151 | 0.00% | 0 | 1.761 / 2.079 / 4.314 (151) | 0.247 / 0.528 / 2.972 (151) | 198.51.100.1 × 151 | 0 |
| baseline | erp_persistent | 21 / 21 | 0.00% | 0 | 0.302 / 0.751 / 3.444 (21) | 0.346 / 0.346 / 0.346 (1) | 198.51.100.1 × 21 | 0 |
| fault | erp_persistent | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp_persistent | 130 / 151 | 13.91% | 21 | 0.288 / 0.548 / 66.271 (130) | — (0) | 198.51.100.1 × 130 | 0 |

| Time relative to fault or repair | Seconds |
| --- | ---: |
| WAN1 service probe failed | — |
| SD-WAN selected WAN2 | — |
| PF loaded and confirmed WAN2 | — |
| WAN1 service probe recovered | — |
| PF loaded and confirmed WAN1 after repair | — |
| backup first sustained replies after repair | 0.234 / 0.734 s |
| dns first sustained replies after repair | 0.233 / 0.733 s |
| erp first sustained replies after repair | 0.234 / 0.734 s |
| erp_persistent first sustained replies after repair | 5.549 / 5.983 s |

| Phase | Native monitor | Samples | RTT ms P50 / P95 / max | RTT deviation ms P50 / P95 / max | Observed loss % P50 / max |
| --- | --- | ---: | --- | --- | --- |
| baseline | GW_A | 6 | 0.221 / 0.248 / 0.248 | 0.085 / 0.099 / 0.099 | 0 / 0 |
| baseline | GW_B | 6 | 0.121 / 0.136 / 0.136 | 0.074 / 0.100 / 0.100 | 0 / 0 |
| fault | GW_A | 12 | 0.185 / 0.244 / 0.244 | 0.112 / 0.214 / 0.214 | 0 / 0 |
| fault | GW_B | 12 | 0.206 / 0.288 / 0.288 | 0.113 / 0.229 / 0.229 | 0 / 0 |
| recovery | GW_A | 38 | 0.175 / 0.241 / 0.244 | 0.106 / 0.377 / 0.383 | 0 / 0 |
| recovery | GW_B | 38 | 0.182 / 0.308 / 0.344 | 0.105 / 0.444 / 0.551 | 0 / 0 |

## Run 2 · sdwan · erp_wan1

Fault window 12.009 s. Recovery window 37.743 s.

| Phase | Flow | OK / total | Failed % | Timeout | Response ms P50 / P95 / max (n) | TCP connect ms P50 / P95 / max (n) | Successful replies by source | Crossed boundary |
| --- | --- | ---: | ---: | ---: | --- | --- | --- | ---: |
| baseline | backup | 21 / 21 | 0.00% | 0 | 1.791 / 2.012 / 2.056 (21) | 0.277 / 0.529 / 0.536 (21) | 198.51.100.1 × 21 | 0 |
| fault | backup | 48 / 48 | 0.00% | 0 | 1.774 / 2.050 / 2.240 (48) | 0.237 / 0.509 / 0.820 (48) | 198.51.100.1 × 48 | 0 |
| recovery | backup | 151 / 151 | 0.00% | 0 | 1.607 / 2.000 / 4.849 (151) | 0.206 / 0.548 / 3.193 (151) | 198.51.100.1 × 151 | 0 |
| baseline | dns | 21 / 21 | 0.00% | 0 | 0.555 / 0.795 / 0.901 (21) | — (0) | — | 0 |
| fault | dns | 48 / 48 | 0.00% | 0 | 0.564 / 0.810 / 1.204 (48) | — (0) | — | 0 |
| recovery | dns | 151 / 151 | 0.00% | 0 | 0.527 / 0.722 / 3.255 (151) | — (0) | — | 0 |
| baseline | erp | 21 / 21 | 0.00% | 0 | 1.746 / 1.946 / 2.007 (21) | 0.238 / 0.501 / 0.567 (21) | 198.51.100.1 × 21 | 0 |
| fault | erp | 35 / 48 | 27.08% | 13 | 1.778 / 2.216 / 2.255 (35) | 0.208 / 0.487 / 0.495 (35) | 203.0.113.1 × 35 | 0 |
| recovery | erp | 151 / 151 | 0.00% | 0 | 1.628 / 1.919 / 4.869 (151) | 0.207 / 0.437 / 3.427 (151) | 198.51.100.1 × 28 — 203.0.113.1 × 123 | 0 |
| baseline | erp_persistent | 21 / 21 | 0.00% | 0 | 0.303 / 0.402 / 1.650 (21) | 0.106 / 0.106 / 0.106 (1) | 198.51.100.1 × 21 | 0 |
| fault | erp_persistent | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp_persistent | 130 / 151 | 13.91% | 21 | 0.259 / 0.599 / 119.119 (130) | — (0) | 198.51.100.1 × 130 | 0 |

| Time relative to fault or repair | Seconds |
| --- | ---: |
| WAN1 service probe failed | 3.293 |
| SD-WAN selected WAN2 | 3.293 |
| PF loaded and confirmed WAN2 | 3.323 |
| WAN1 service probe recovered | 0.773 |
| PF loaded and confirmed WAN1 after repair | 30.801 |
| backup first sustained replies after repair | 0.234 / 0.734 s |
| dns first sustained replies after repair | 0.233 / 0.732 s |
| erp first sustained replies after repair | 0.233 / 0.734 s |
| erp_persistent first sustained replies after repair | 5.601 / 5.982 s |

| Phase | Native monitor | Samples | RTT ms P50 / P95 / max | RTT deviation ms P50 / P95 / max | Observed loss % P50 / max |
| --- | --- | ---: | --- | --- | --- |
| baseline | GW_A | 6 | 0.168 / 0.178 / 0.178 | 0.097 / 0.121 / 0.121 | 0 / 0 |
| baseline | GW_B | 6 | 0.181 / 0.204 / 0.204 | 0.120 / 0.136 / 0.136 | 0 / 0 |
| fault | GW_A | 4 | 0.151 / 0.186 / 0.186 | 0.100 / 0.133 / 0.133 | 0 / 0 |
| fault | GW_B | 4 | 0.142 / 0.233 / 0.233 | 0.098 / 0.170 / 0.170 | 0 / 0 |
| recovery | GW_A | 37 | 0.151 / 0.343 / 0.421 | 0.105 / 0.443 / 0.597 | 0 / 0 |
| recovery | GW_B | 37 | 0.142 / 0.248 / 0.255 | 0.093 / 0.146 / 0.155 | 0 / 0 |

## Run 3 · sdwan · erp_wan1

Fault window 12.009 s. Recovery window 37.769 s.

| Phase | Flow | OK / total | Failed % | Timeout | Response ms P50 / P95 / max (n) | TCP connect ms P50 / P95 / max (n) | Successful replies by source | Crossed boundary |
| --- | --- | ---: | ---: | ---: | --- | --- | --- | ---: |
| baseline | backup | 21 / 21 | 0.00% | 0 | 1.672 / 1.849 / 1.855 (21) | 0.243 / 0.429 / 0.449 (21) | 198.51.100.1 × 21 | 0 |
| fault | backup | 48 / 48 | 0.00% | 0 | 1.577 / 1.890 / 2.000 (48) | 0.197 / 0.374 / 0.523 (48) | 198.51.100.1 × 48 | 0 |
| recovery | backup | 151 / 151 | 0.00% | 0 | 1.471 / 1.944 / 2.711 (151) | 0.177 / 0.456 / 1.458 (151) | 198.51.100.1 × 151 | 0 |
| baseline | dns | 21 / 21 | 0.00% | 0 | 0.589 / 0.858 / 0.872 (21) | — (0) | — | 0 |
| fault | dns | 48 / 48 | 0.00% | 0 | 0.518 / 0.742 / 0.804 (48) | — (0) | — | 0 |
| recovery | dns | 151 / 151 | 0.00% | 0 | 0.436 / 0.709 / 0.927 (151) | — (0) | — | 0 |
| baseline | erp | 21 / 21 | 0.00% | 0 | 1.614 / 1.951 / 1.959 (21) | 0.234 / 0.423 / 0.579 (21) | 198.51.100.1 × 21 | 0 |
| fault | erp | 35 / 48 | 27.08% | 13 | 1.653 / 1.951 / 1.967 (35) | 0.222 / 0.298 / 0.301 (35) | 203.0.113.1 × 35 | 0 |
| recovery | erp | 151 / 151 | 0.00% | 0 | 1.454 / 1.873 / 2.132 (151) | 0.189 / 0.358 / 0.569 (151) | 198.51.100.1 × 28 — 203.0.113.1 × 123 | 0 |
| baseline | erp_persistent | 21 / 21 | 0.00% | 0 | 0.303 / 0.703 / 1.541 (21) | 0.162 / 0.162 / 0.162 (1) | 198.51.100.1 × 21 | 0 |
| fault | erp_persistent | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp_persistent | 129 / 151 | 14.57% | 22 | 0.223 / 0.412 / 0.586 (129) | — (0) | 198.51.100.1 × 129 | 0 |

| Time relative to fault or repair | Seconds |
| --- | ---: |
| WAN1 service probe failed | 3.287 |
| SD-WAN selected WAN2 | 3.287 |
| PF loaded and confirmed WAN2 | 3.317 |
| WAN1 service probe recovered | 0.768 |
| PF loaded and confirmed WAN1 after repair | 30.797 |
| backup first sustained replies after repair | 0.234 / 0.734 s |
| dns first sustained replies after repair | 0.233 / 0.733 s |
| erp first sustained replies after repair | 0.234 / 0.734 s |
| erp_persistent first sustained replies after repair | 5.733 / 6.233 s |

| Phase | Native monitor | Samples | RTT ms P50 / P95 / max | RTT deviation ms P50 / P95 / max | Observed loss % P50 / max |
| --- | --- | ---: | --- | --- | --- |
| baseline | GW_A | 6 | 0.157 / 0.173 / 0.173 | 0.101 / 0.115 / 0.115 | 0 / 0 |
| baseline | GW_B | 6 | 0.167 / 0.222 / 0.222 | 0.108 / 0.139 / 0.139 | 0 / 0 |
| fault | GW_A | 4 | 0.169 / 0.332 / 0.332 | 0.114 / 1.024 / 1.024 | 0 / 0 |
| fault | GW_B | 4 | 0.168 / 0.325 / 0.325 | 0.117 / 1.020 / 1.020 | 0 / 0 |
| recovery | GW_A | 38 | 0.174 / 0.270 / 0.282 | 0.116 / 0.665 / 0.669 | 0 / 0 |
| recovery | GW_B | 38 | 0.172 / 0.289 / 0.317 | 0.115 / 0.662 / 0.664 | 0 / 0 |

## Run 4 · native · erp_wan1

Fault window 12.009 s. Recovery window 37.743 s.

| Phase | Flow | OK / total | Failed % | Timeout | Response ms P50 / P95 / max (n) | TCP connect ms P50 / P95 / max (n) | Successful replies by source | Crossed boundary |
| --- | --- | ---: | ---: | ---: | --- | --- | --- | ---: |
| baseline | backup | 21 / 21 | 0.00% | 0 | 1.462 / 1.780 / 2.033 (21) | 0.166 / 0.291 / 0.299 (21) | 198.51.100.1 × 21 | 0 |
| fault | backup | 48 / 48 | 0.00% | 0 | 1.328 / 1.618 / 2.025 (48) | 0.135 / 0.295 / 0.770 (48) | 198.51.100.1 × 48 | 0 |
| recovery | backup | 151 / 151 | 0.00% | 0 | 1.503 / 1.819 / 2.025 (151) | 0.171 / 0.453 / 0.736 (151) | 198.51.100.1 × 151 | 0 |
| baseline | dns | 21 / 21 | 0.00% | 0 | 0.399 / 0.561 / 0.622 (21) | — (0) | — | 0 |
| fault | dns | 48 / 48 | 0.00% | 0 | 0.377 / 0.560 / 0.837 (48) | — (0) | — | 0 |
| recovery | dns | 151 / 151 | 0.00% | 0 | 0.408 / 0.663 / 2.586 (151) | — (0) | — | 0 |
| baseline | erp | 21 / 21 | 0.00% | 0 | 1.464 / 1.792 / 1.955 (21) | 0.153 / 0.350 / 0.391 (21) | 198.51.100.1 × 21 | 0 |
| fault | erp | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp | 151 / 151 | 0.00% | 0 | 1.479 / 1.739 / 2.261 (151) | 0.187 / 0.379 / 0.774 (151) | 198.51.100.1 × 151 | 0 |
| baseline | erp_persistent | 21 / 21 | 0.00% | 0 | 0.227 / 0.421 / 1.575 (21) | 0.242 / 0.242 / 0.242 (1) | 198.51.100.1 × 21 | 0 |
| fault | erp_persistent | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp_persistent | 130 / 151 | 13.91% | 21 | 0.218 / 0.356 / 76.053 (130) | — (0) | 198.51.100.1 × 130 | 0 |

| Time relative to fault or repair | Seconds |
| --- | ---: |
| WAN1 service probe failed | — |
| SD-WAN selected WAN2 | — |
| PF loaded and confirmed WAN2 | — |
| WAN1 service probe recovered | — |
| PF loaded and confirmed WAN1 after repair | — |
| backup first sustained replies after repair | 0.233 / 0.733 s |
| dns first sustained replies after repair | 0.232 / 0.732 s |
| erp first sustained replies after repair | 0.233 / 0.733 s |
| erp_persistent first sustained replies after repair | 5.557 / 5.981 s |

| Phase | Native monitor | Samples | RTT ms P50 / P95 / max | RTT deviation ms P50 / P95 / max | Observed loss % P50 / max |
| --- | --- | ---: | --- | --- | --- |
| baseline | GW_A | 6 | 0.108 / 0.243 / 0.243 | 0.073 / 0.119 / 0.119 | 0 / 0 |
| baseline | GW_B | 6 | 0.105 / 0.169 / 0.169 | 0.081 / 0.133 / 0.133 | 0 / 0 |
| fault | GW_A | 12 | 0.142 / 0.200 / 0.200 | 0.099 / 0.147 / 0.147 | 0 / 0 |
| fault | GW_B | 12 | 0.125 / 0.266 / 0.266 | 0.096 / 0.132 / 0.132 | 0 / 0 |
| recovery | GW_A | 37 | 0.144 / 0.207 / 0.216 | 0.103 / 0.147 / 0.155 | 0 / 0 |
| recovery | GW_B | 37 | 0.153 / 0.222 / 0.225 | 0.105 / 0.151 / 0.161 | 0 / 0 |

## Run 5 · native · erp_wan1

Fault window 12.009 s. Recovery window 37.755 s.

| Phase | Flow | OK / total | Failed % | Timeout | Response ms P50 / P95 / max (n) | TCP connect ms P50 / P95 / max (n) | Successful replies by source | Crossed boundary |
| --- | --- | ---: | ---: | ---: | --- | --- | --- | ---: |
| baseline | backup | 21 / 21 | 0.00% | 0 | 1.598 / 1.949 / 2.030 (21) | 0.260 / 0.437 / 0.485 (21) | 198.51.100.1 × 21 | 0 |
| fault | backup | 48 / 48 | 0.00% | 0 | 1.610 / 1.913 / 2.069 (48) | 0.208 / 0.377 / 0.637 (48) | 198.51.100.1 × 48 | 0 |
| recovery | backup | 151 / 151 | 0.00% | 0 | 1.688 / 2.014 / 2.272 (151) | 0.224 / 0.418 / 1.831 (151) | 198.51.100.1 × 151 | 0 |
| baseline | dns | 21 / 21 | 0.00% | 0 | 0.477 / 0.590 / 0.695 (21) | — (0) | — | 0 |
| fault | dns | 48 / 48 | 0.00% | 0 | 0.554 / 0.879 / 0.932 (48) | — (0) | — | 0 |
| recovery | dns | 151 / 151 | 0.00% | 0 | 0.523 / 0.717 / 0.948 (151) | — (0) | — | 0 |
| baseline | erp | 21 / 21 | 0.00% | 0 | 1.615 / 1.799 / 1.946 (21) | 0.167 / 0.359 / 0.435 (21) | 198.51.100.1 × 21 | 0 |
| fault | erp | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp | 151 / 151 | 0.00% | 0 | 1.672 / 2.010 / 2.126 (151) | 0.214 / 0.357 / 0.505 (151) | 198.51.100.1 × 151 | 0 |
| baseline | erp_persistent | 21 / 21 | 0.00% | 0 | 0.244 / 0.332 / 1.653 (21) | 0.313 / 0.313 / 0.313 (1) | 198.51.100.1 × 21 | 0 |
| fault | erp_persistent | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp_persistent | 130 / 151 | 13.91% | 21 | 0.252 / 0.421 / 96.848 (130) | — (0) | 198.51.100.1 × 130 | 0 |

| Time relative to fault or repair | Seconds |
| --- | ---: |
| WAN1 service probe failed | — |
| SD-WAN selected WAN2 | — |
| PF loaded and confirmed WAN2 | — |
| WAN1 service probe recovered | — |
| PF loaded and confirmed WAN1 after repair | — |
| backup first sustained replies after repair | 0.233 / 0.733 s |
| dns first sustained replies after repair | 0.232 / 0.732 s |
| erp first sustained replies after repair | 0.233 / 0.733 s |
| erp_persistent first sustained replies after repair | 5.579 / 5.982 s |

| Phase | Native monitor | Samples | RTT ms P50 / P95 / max | RTT deviation ms P50 / P95 / max | Observed loss % P50 / max |
| --- | --- | ---: | --- | --- | --- |
| baseline | GW_A | 6 | 0.107 / 0.146 / 0.146 | 0.098 / 0.135 / 0.135 | 0 / 0 |
| baseline | GW_B | 6 | 0.124 / 0.154 / 0.154 | 0.096 / 0.119 / 0.119 | 0 / 0 |
| fault | GW_A | 12 | 0.145 / 0.229 / 0.229 | 0.095 / 0.122 / 0.122 | 0 / 0 |
| fault | GW_B | 12 | 0.149 / 0.269 / 0.269 | 0.107 / 0.154 / 0.154 | 0 / 0 |
| recovery | GW_A | 38 | 0.168 / 0.236 / 0.247 | 0.108 / 0.262 / 0.264 | 0 / 0 |
| recovery | GW_B | 38 | 0.133 / 0.189 / 0.196 | 0.098 / 0.233 / 0.233 | 0 / 0 |

## Run 6 · sdwan · erp_wan1

Fault window 12.009 s. Recovery window 37.745 s.

| Phase | Flow | OK / total | Failed % | Timeout | Response ms P50 / P95 / max (n) | TCP connect ms P50 / P95 / max (n) | Successful replies by source | Crossed boundary |
| --- | --- | ---: | ---: | ---: | --- | --- | --- | ---: |
| baseline | backup | 21 / 21 | 0.00% | 0 | 1.680 / 1.815 / 1.846 (21) | 0.244 / 0.425 / 0.441 (21) | 198.51.100.1 × 21 | 0 |
| fault | backup | 48 / 48 | 0.00% | 0 | 1.533 / 1.873 / 1.887 (48) | 0.183 / 0.358 / 0.388 (48) | 198.51.100.1 × 48 | 0 |
| recovery | backup | 151 / 151 | 0.00% | 0 | 1.361 / 1.606 / 1.930 (151) | 0.157 / 0.287 / 0.439 (151) | 198.51.100.1 × 151 | 0 |
| baseline | dns | 21 / 21 | 0.00% | 0 | 0.482 / 0.636 / 0.669 (21) | — (0) | — | 0 |
| fault | dns | 48 / 48 | 0.00% | 0 | 0.480 / 0.731 / 0.932 (48) | — (0) | — | 0 |
| recovery | dns | 151 / 151 | 0.00% | 0 | 0.371 / 0.595 / 1.478 (151) | — (0) | — | 0 |
| baseline | erp | 21 / 21 | 0.00% | 0 | 1.586 / 1.863 / 1.876 (21) | 0.253 / 0.442 / 0.443 (21) | 198.51.100.1 × 21 | 0 |
| fault | erp | 35 / 48 | 27.08% | 13 | 1.594 / 1.940 / 1.945 (35) | 0.189 / 0.400 / 0.436 (35) | 203.0.113.1 × 35 | 0 |
| recovery | erp | 151 / 151 | 0.00% | 0 | 1.391 / 1.632 / 1.833 (151) | 0.172 / 0.341 / 0.693 (151) | 198.51.100.1 × 28 — 203.0.113.1 × 123 | 0 |
| baseline | erp_persistent | 21 / 21 | 0.00% | 0 | 0.245 / 0.479 / 1.426 (21) | 0.391 / 0.391 / 0.391 (1) | 198.51.100.1 × 21 | 0 |
| fault | erp_persistent | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp_persistent | 129 / 151 | 14.57% | 22 | 0.186 / 0.289 / 0.519 (129) | — (0) | 198.51.100.1 × 129 | 0 |

| Time relative to fault or repair | Seconds |
| --- | ---: |
| WAN1 service probe failed | 3.290 |
| SD-WAN selected WAN2 | 3.290 |
| PF loaded and confirmed WAN2 | 3.320 |
| WAN1 service probe recovered | 0.771 |
| PF loaded and confirmed WAN1 after repair | 30.801 |
| backup first sustained replies after repair | 0.233 / 0.733 s |
| dns first sustained replies after repair | 0.232 / 0.732 s |
| erp first sustained replies after repair | 0.233 / 0.733 s |
| erp_persistent first sustained replies after repair | 5.732 / 6.232 s |

| Phase | Native monitor | Samples | RTT ms P50 / P95 / max | RTT deviation ms P50 / P95 / max | Observed loss % P50 / max |
| --- | --- | ---: | --- | --- | --- |
| baseline | GW_A | 6 | 0.106 / 0.111 / 0.111 | 0.088 / 0.107 / 0.107 | 0 / 0 |
| baseline | GW_B | 6 | 0.106 / 0.114 / 0.114 | 0.084 / 0.098 / 0.098 | 0 / 0 |
| fault | GW_A | 4 | 0.118 / 0.167 / 0.167 | 0.086 / 0.112 / 0.112 | 0 / 0 |
| fault | GW_B | 4 | 0.148 / 0.155 / 0.155 | 0.091 / 0.123 / 0.123 | 0 / 0 |
| recovery | GW_A | 37 | 0.121 / 0.211 / 0.219 | 0.097 / 0.199 / 0.199 | 0 / 0 |
| recovery | GW_B | 37 | 0.144 / 0.220 / 0.230 | 0.104 / 0.189 / 0.203 | 0 / 0 |
