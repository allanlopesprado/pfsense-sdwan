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
| 2 | erp_wan1 | sdwan | 3.492 / 3.993 s | 0.234 / 0.734 s | 30.984 / 31.484 s | yes |
| 3 | erp_wan1 | sdwan | 3.492 / 3.993 s | 0.233 / 0.733 s | 30.983 / 31.483 s | yes |
| 4 | erp_wan1 | native | not observed in 12.009 s (47 completed attempts) | 0.233 / 0.734 s | 0.233 / 0.734 s | no |
| 5 | erp_wan1 | native | not observed in 12.009 s (47 completed attempts) | 0.233 / 0.733 s | 0.233 / 0.733 s | no |
| 6 | erp_wan1 | sdwan | 3.492 / 3.992 s | 0.234 / 0.733 s | 30.983 / 31.483 s | yes |

## Pooled traffic measurements

| Scenario | Mode | Runs | Phase | Flow | OK / total | Failed % | Timeout | Response ms P50 / P95 / max (n) | TCP connect ms P50 / P95 / max (n) | Successful replies by source | Crossed boundary |
| --- | --- | ---: | --- | --- | ---: | ---: | ---: | --- | --- | --- | ---: |
| erp_wan1 | native | 3 | baseline | backup | 63 / 63 | 0.00% | 0 | 1.839 / 2.155 / 2.441 (63) | 0.324 / 0.550 / 0.814 (63) | 198.51.100.1 × 63 | 0 |
| erp_wan1 | native | 3 | baseline | dns | 63 / 63 | 0.00% | 0 | 0.626 / 0.891 / 1.266 (63) | — (0) | — | 0 |
| erp_wan1 | native | 3 | baseline | erp | 63 / 63 | 0.00% | 0 | 1.891 / 2.288 / 2.453 (63) | 0.313 / 0.588 / 1.300 (63) | 198.51.100.1 × 63 | 0 |
| erp_wan1 | native | 3 | baseline | erp_persistent | 63 / 63 | 0.00% | 0 | 0.345 / 0.896 / 2.302 (63) | 0.286 / 0.489 / 0.489 (3) | 198.51.100.1 × 63 | 0 |
| erp_wan1 | native | 3 | fault | backup | 144 / 144 | 0.00% | 0 | 1.661 / 1.873 / 2.160 (144) | 0.252 / 0.402 / 0.517 (144) | 198.51.100.1 × 144 | 0 |
| erp_wan1 | native | 3 | fault | dns | 144 / 144 | 0.00% | 0 | 0.636 / 0.848 / 0.926 (144) | — (0) | — | 0 |
| erp_wan1 | native | 3 | fault | erp | 0 / 144 | 100.00% | 144 | — (0) | — (0) | — | 3 |
| erp_wan1 | native | 3 | fault | erp_persistent | 0 / 144 | 100.00% | 144 | — (0) | — (0) | — | 3 |
| erp_wan1 | native | 3 | recovery | backup | 453 / 453 | 0.00% | 0 | 1.808 / 2.263 / 2.518 (453) | 0.280 / 0.538 / 0.784 (453) | 198.51.100.1 × 453 | 0 |
| erp_wan1 | native | 3 | recovery | dns | 453 / 453 | 0.00% | 0 | 0.627 / 0.894 / 1.973 (453) | — (0) | — | 0 |
| erp_wan1 | native | 3 | recovery | erp | 452 / 453 | 0.22% | 1 | 1.824 / 2.270 / 2.427 (452) | 0.296 / 0.516 / 0.707 (452) | 198.51.100.1 × 452 | 0 |
| erp_wan1 | native | 3 | recovery | erp_persistent | 390 / 453 | 13.91% | 63 | 0.339 / 0.547 / 157.120 (390) | — (0) | 198.51.100.1 × 390 | 0 |
| erp_wan1 | sdwan | 3 | baseline | backup | 63 / 63 | 0.00% | 0 | 1.877 / 2.274 / 2.487 (63) | 0.298 / 0.497 / 0.663 (63) | 198.51.100.1 × 63 | 0 |
| erp_wan1 | sdwan | 3 | baseline | dns | 63 / 63 | 0.00% | 0 | 0.625 / 0.824 / 0.911 (63) | — (0) | — | 0 |
| erp_wan1 | sdwan | 3 | baseline | erp | 63 / 63 | 0.00% | 0 | 1.914 / 2.237 / 2.372 (63) | 0.289 / 0.568 / 0.884 (63) | 198.51.100.1 × 63 | 0 |
| erp_wan1 | sdwan | 3 | baseline | erp_persistent | 63 / 63 | 0.00% | 0 | 0.366 / 0.872 / 1.862 (63) | 0.285 / 0.451 / 0.451 (3) | 198.51.100.1 × 63 | 0 |
| erp_wan1 | sdwan | 3 | fault | backup | 144 / 144 | 0.00% | 0 | 1.799 / 2.171 / 2.342 (144) | 0.260 / 0.425 / 0.493 (144) | 198.51.100.1 × 144 | 0 |
| erp_wan1 | sdwan | 3 | fault | dns | 144 / 144 | 0.00% | 0 | 0.634 / 0.815 / 1.173 (144) | — (0) | — | 0 |
| erp_wan1 | sdwan | 3 | fault | erp | 105 / 144 | 27.08% | 39 | 1.811 / 2.243 / 2.481 (105) | 0.237 / 0.403 / 0.499 (105) | 203.0.113.1 × 105 | 0 |
| erp_wan1 | sdwan | 3 | fault | erp_persistent | 0 / 144 | 100.00% | 144 | — (0) | — (0) | — | 3 |
| erp_wan1 | sdwan | 3 | recovery | backup | 453 / 453 | 0.00% | 0 | 1.855 / 2.285 / 2.564 (453) | 0.273 / 0.552 / 1.229 (453) | 198.51.100.1 × 453 | 0 |
| erp_wan1 | sdwan | 3 | recovery | dns | 453 / 453 | 0.00% | 0 | 0.625 / 0.889 / 2.712 (453) | — (0) | — | 0 |
| erp_wan1 | sdwan | 3 | recovery | erp | 452 / 453 | 0.22% | 1 | 1.868 / 2.253 / 2.560 (452) | 0.284 / 0.531 / 0.973 (452) | 198.51.100.1 × 84 — 203.0.113.1 × 368 | 0 |
| erp_wan1 | sdwan | 3 | recovery | erp_persistent | 390 / 453 | 13.91% | 63 | 0.327 / 0.512 / 79.292 (390) | — (0) | 198.51.100.1 × 390 | 0 |

## Run 1 · native · erp_wan1

Fault window 12.009 s. Recovery window 37.750 s.

| Phase | Flow | OK / total | Failed % | Timeout | Response ms P50 / P95 / max (n) | TCP connect ms P50 / P95 / max (n) | Successful replies by source | Crossed boundary |
| --- | --- | ---: | ---: | ---: | --- | --- | --- | ---: |
| baseline | backup | 21 / 21 | 0.00% | 0 | 1.913 / 2.050 / 2.059 (21) | 0.331 / 0.620 / 0.814 (21) | 198.51.100.1 × 21 | 0 |
| fault | backup | 48 / 48 | 0.00% | 0 | 1.679 / 1.827 / 1.927 (48) | 0.243 / 0.376 / 0.452 (48) | 198.51.100.1 × 48 | 0 |
| recovery | backup | 151 / 151 | 0.00% | 0 | 1.840 / 2.339 / 2.453 (151) | 0.274 / 0.535 / 0.674 (151) | 198.51.100.1 × 151 | 0 |
| baseline | dns | 21 / 21 | 0.00% | 0 | 0.646 / 1.042 / 1.266 (21) | — (0) | — | 0 |
| fault | dns | 48 / 48 | 0.00% | 0 | 0.632 / 0.839 / 0.897 (48) | — (0) | — | 0 |
| recovery | dns | 151 / 151 | 0.00% | 0 | 0.619 / 0.903 / 1.973 (151) | — (0) | — | 0 |
| baseline | erp | 21 / 21 | 0.00% | 0 | 1.974 / 2.264 / 2.361 (21) | 0.294 / 0.476 / 0.604 (21) | 198.51.100.1 × 21 | 0 |
| fault | erp | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp | 150 / 151 | 0.66% | 1 | 1.857 / 2.300 / 2.406 (150) | 0.297 / 0.502 / 0.638 (150) | 198.51.100.1 × 150 | 0 |
| baseline | erp_persistent | 21 / 21 | 0.00% | 0 | 0.345 / 0.602 / 2.302 (21) | 0.489 / 0.489 / 0.489 (1) | 198.51.100.1 × 21 | 0 |
| fault | erp_persistent | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp_persistent | 130 / 151 | 13.91% | 21 | 0.332 / 0.525 / 46.406 (130) | — (0) | 198.51.100.1 × 130 | 0 |

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
| erp_persistent first sustained replies after repair | 5.529 / 5.983 s |

| Phase | Native monitor | Samples | RTT ms P50 / P95 / max | RTT deviation ms P50 / P95 / max | Observed loss % P50 / max |
| --- | --- | ---: | --- | --- | --- |
| baseline | GW_A | 6 | 0.182 / 0.358 / 0.358 | 0.054 / 0.345 / 0.345 | 0 / 0 |
| baseline | GW_B | 6 | 0.110 / 0.130 / 0.130 | 0.034 / 0.036 / 0.036 | 0 / 0 |
| fault | GW_A | 12 | 0.165 / 0.193 / 0.193 | 0.061 / 0.118 / 0.118 | 0 / 0 |
| fault | GW_B | 12 | 0.151 / 0.217 / 0.217 | 0.056 / 0.163 / 0.163 | 0 / 0 |
| recovery | GW_A | 38 | 0.155 / 0.204 / 0.211 | 0.052 / 0.122 / 0.142 | 0 / 0 |
| recovery | GW_B | 38 | 0.131 / 0.210 / 0.215 | 0.052 / 0.159 / 0.169 | 0 / 0 |

## Run 2 · sdwan · erp_wan1

Fault window 12.009 s. Recovery window 37.767 s.

| Phase | Flow | OK / total | Failed % | Timeout | Response ms P50 / P95 / max (n) | TCP connect ms P50 / P95 / max (n) | Successful replies by source | Crossed boundary |
| --- | --- | ---: | ---: | ---: | --- | --- | --- | ---: |
| baseline | backup | 21 / 21 | 0.00% | 0 | 1.906 / 2.347 / 2.487 (21) | 0.319 / 0.587 / 0.663 (21) | 198.51.100.1 × 21 | 0 |
| fault | backup | 48 / 48 | 0.00% | 0 | 1.832 / 2.241 / 2.294 (48) | 0.265 / 0.428 / 0.479 (48) | 198.51.100.1 × 48 | 0 |
| recovery | backup | 151 / 151 | 0.00% | 0 | 1.852 / 2.302 / 2.458 (151) | 0.295 / 0.510 / 0.643 (151) | 198.51.100.1 × 151 | 0 |
| baseline | dns | 21 / 21 | 0.00% | 0 | 0.668 / 0.757 / 0.863 (21) | — (0) | — | 0 |
| fault | dns | 48 / 48 | 0.00% | 0 | 0.640 / 0.808 / 0.853 (48) | — (0) | — | 0 |
| recovery | dns | 151 / 151 | 0.00% | 0 | 0.616 / 0.862 / 2.712 (151) | — (0) | — | 0 |
| baseline | erp | 21 / 21 | 0.00% | 0 | 2.065 / 2.239 / 2.372 (21) | 0.323 / 0.557 / 0.578 (21) | 198.51.100.1 × 21 | 0 |
| fault | erp | 35 / 48 | 27.08% | 13 | 1.913 / 2.424 / 2.481 (35) | 0.235 / 0.429 / 0.499 (35) | 203.0.113.1 × 35 | 0 |
| recovery | erp | 150 / 151 | 0.66% | 1 | 1.852 / 2.266 / 2.560 (150) | 0.289 / 0.455 / 0.591 (150) | 198.51.100.1 × 28 — 203.0.113.1 × 122 | 0 |
| baseline | erp_persistent | 21 / 21 | 0.00% | 0 | 0.366 / 0.520 / 1.765 (21) | 0.125 / 0.125 / 0.125 (1) | 198.51.100.1 × 21 | 0 |
| fault | erp_persistent | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp_persistent | 130 / 151 | 13.91% | 21 | 0.326 / 0.486 / 44.022 (130) | — (0) | 198.51.100.1 × 130 | 0 |

| Time relative to fault or repair | Seconds |
| --- | ---: |
| WAN1 service probe failed | 3.282 |
| SD-WAN selected WAN2 | 3.282 |
| PF loaded and confirmed WAN2 | 3.321 |
| WAN1 service probe recovered | 0.765 |
| PF loaded and confirmed WAN1 after repair | 30.804 |
| backup first sustained replies after repair | 0.234 / 0.734 s |
| dns first sustained replies after repair | 0.233 / 0.733 s |
| erp first sustained replies after repair | 0.234 / 0.734 s |
| erp_persistent first sustained replies after repair | 5.526 / 5.982 s |

| Phase | Native monitor | Samples | RTT ms P50 / P95 / max | RTT deviation ms P50 / P95 / max | Observed loss % P50 / max |
| --- | --- | ---: | --- | --- | --- |
| baseline | GW_A | 6 | 0.147 / 0.185 / 0.185 | 0.059 / 0.069 / 0.069 | 0 / 0 |
| baseline | GW_B | 6 | 0.199 / 0.221 / 0.221 | 0.054 / 0.068 / 0.068 | 0 / 0 |
| fault | GW_A | 4 | 0.181 / 0.189 / 0.189 | 0.053 / 0.059 / 0.059 | 0 / 0 |
| fault | GW_B | 4 | 0.114 / 0.135 / 0.135 | 0.035 / 0.067 / 0.067 | 0 / 0 |
| recovery | GW_A | 38 | 0.159 / 0.194 / 0.196 | 0.049 / 0.071 / 0.073 | 0 / 0 |
| recovery | GW_B | 38 | 0.154 / 0.189 / 0.196 | 0.057 / 0.070 / 0.074 | 0 / 0 |

## Run 3 · sdwan · erp_wan1

Fault window 12.009 s. Recovery window 37.765 s.

| Phase | Flow | OK / total | Failed % | Timeout | Response ms P50 / P95 / max (n) | TCP connect ms P50 / P95 / max (n) | Successful replies by source | Crossed boundary |
| --- | --- | ---: | ---: | ---: | --- | --- | --- | ---: |
| baseline | backup | 21 / 21 | 0.00% | 0 | 1.878 / 2.262 / 2.277 (21) | 0.295 / 0.439 / 0.614 (21) | 198.51.100.1 × 21 | 0 |
| fault | backup | 48 / 48 | 0.00% | 0 | 1.825 / 2.094 / 2.253 (48) | 0.242 / 0.388 / 0.425 (48) | 198.51.100.1 × 48 | 0 |
| recovery | backup | 151 / 151 | 0.00% | 0 | 1.875 / 2.200 / 2.559 (151) | 0.273 / 0.580 / 0.677 (151) | 198.51.100.1 × 151 | 0 |
| baseline | dns | 21 / 21 | 0.00% | 0 | 0.607 / 0.824 / 0.911 (21) | — (0) | — | 0 |
| fault | dns | 48 / 48 | 0.00% | 0 | 0.616 / 0.822 / 1.173 (48) | — (0) | — | 0 |
| recovery | dns | 151 / 151 | 0.00% | 0 | 0.637 / 0.939 / 1.547 (151) | — (0) | — | 0 |
| baseline | erp | 21 / 21 | 0.00% | 0 | 1.833 / 2.204 / 2.248 (21) | 0.257 / 0.546 / 0.568 (21) | 198.51.100.1 × 21 | 0 |
| fault | erp | 35 / 48 | 27.08% | 13 | 1.793 / 2.166 / 2.223 (35) | 0.261 / 0.384 / 0.429 (35) | 203.0.113.1 × 35 | 0 |
| recovery | erp | 151 / 151 | 0.00% | 0 | 1.896 / 2.255 / 2.538 (151) | 0.284 / 0.612 / 0.973 (151) | 198.51.100.1 × 28 — 203.0.113.1 × 123 | 0 |
| baseline | erp_persistent | 21 / 21 | 0.00% | 0 | 0.415 / 0.872 / 1.674 (21) | 0.285 / 0.285 / 0.285 (1) | 198.51.100.1 × 21 | 0 |
| fault | erp_persistent | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp_persistent | 130 / 151 | 13.91% | 21 | 0.331 / 0.536 / 79.292 (130) | — (0) | 198.51.100.1 × 130 | 0 |

| Time relative to fault or repair | Seconds |
| --- | ---: |
| WAN1 service probe failed | 3.282 |
| SD-WAN selected WAN2 | 3.282 |
| PF loaded and confirmed WAN2 | 3.321 |
| WAN1 service probe recovered | 0.765 |
| PF loaded and confirmed WAN1 after repair | 30.804 |
| backup first sustained replies after repair | 0.234 / 0.733 s |
| dns first sustained replies after repair | 0.232 / 0.733 s |
| erp first sustained replies after repair | 0.233 / 0.733 s |
| erp_persistent first sustained replies after repair | 5.561 / 5.982 s |

| Phase | Native monitor | Samples | RTT ms P50 / P95 / max | RTT deviation ms P50 / P95 / max | Observed loss % P50 / max |
| --- | --- | ---: | --- | --- | --- |
| baseline | GW_A | 6 | 0.179 / 0.197 / 0.197 | 0.062 / 0.068 / 0.068 | 0 / 0 |
| baseline | GW_B | 6 | 0.134 / 0.167 / 0.167 | 0.049 / 0.061 / 0.061 | 0 / 0 |
| fault | GW_A | 4 | 0.156 / 0.163 / 0.163 | 0.058 / 0.112 / 0.112 | 0 / 0 |
| fault | GW_B | 4 | 0.114 / 0.143 / 0.143 | 0.046 / 0.075 / 0.075 | 0 / 0 |
| recovery | GW_A | 38 | 0.172 / 0.215 / 0.218 | 0.051 / 0.080 / 0.085 | 0 / 0 |
| recovery | GW_B | 38 | 0.125 / 0.164 / 0.176 | 0.041 / 0.065 / 0.067 | 0 / 0 |

## Run 4 · native · erp_wan1

Fault window 12.009 s. Recovery window 37.750 s.

| Phase | Flow | OK / total | Failed % | Timeout | Response ms P50 / P95 / max (n) | TCP connect ms P50 / P95 / max (n) | Successful replies by source | Crossed boundary |
| --- | --- | ---: | ---: | ---: | --- | --- | --- | ---: |
| baseline | backup | 21 / 21 | 0.00% | 0 | 1.886 / 2.303 / 2.441 (21) | 0.328 / 0.513 / 0.656 (21) | 198.51.100.1 × 21 | 0 |
| fault | backup | 48 / 48 | 0.00% | 0 | 1.679 / 1.906 / 1.916 (48) | 0.274 / 0.388 / 0.439 (48) | 198.51.100.1 × 48 | 0 |
| recovery | backup | 151 / 151 | 0.00% | 0 | 1.765 / 2.223 / 2.518 (151) | 0.262 / 0.539 / 0.763 (151) | 198.51.100.1 × 151 | 0 |
| baseline | dns | 21 / 21 | 0.00% | 0 | 0.655 / 0.891 / 0.998 (21) | — (0) | — | 0 |
| fault | dns | 48 / 48 | 0.00% | 0 | 0.664 / 0.872 / 0.926 (48) | — (0) | — | 0 |
| recovery | dns | 151 / 151 | 0.00% | 0 | 0.630 / 0.928 / 0.997 (151) | — (0) | — | 0 |
| baseline | erp | 21 / 21 | 0.00% | 0 | 1.903 / 2.326 / 2.453 (21) | 0.313 / 0.735 / 1.300 (21) | 198.51.100.1 × 21 | 0 |
| fault | erp | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp | 151 / 151 | 0.00% | 0 | 1.809 / 2.200 / 2.427 (151) | 0.283 / 0.510 / 0.665 (151) | 198.51.100.1 × 151 | 0 |
| baseline | erp_persistent | 21 / 21 | 0.00% | 0 | 0.361 / 0.896 / 2.258 (21) | 0.286 / 0.286 / 0.286 (1) | 198.51.100.1 × 21 | 0 |
| fault | erp_persistent | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp_persistent | 130 / 151 | 13.91% | 21 | 0.347 / 0.553 / 83.071 (130) | — (0) | 198.51.100.1 × 130 | 0 |

| Time relative to fault or repair | Seconds |
| --- | ---: |
| WAN1 service probe failed | — |
| SD-WAN selected WAN2 | — |
| PF loaded and confirmed WAN2 | — |
| WAN1 service probe recovered | — |
| PF loaded and confirmed WAN1 after repair | — |
| backup first sustained replies after repair | 0.234 / 0.734 s |
| dns first sustained replies after repair | 0.233 / 0.732 s |
| erp first sustained replies after repair | 0.233 / 0.734 s |
| erp_persistent first sustained replies after repair | 5.565 / 5.983 s |

| Phase | Native monitor | Samples | RTT ms P50 / P95 / max | RTT deviation ms P50 / P95 / max | Observed loss % P50 / max |
| --- | --- | ---: | --- | --- | --- |
| baseline | GW_A | 6 | 0.134 / 0.176 / 0.176 | 0.036 / 0.060 / 0.060 | 0 / 0 |
| baseline | GW_B | 6 | 0.138 / 0.150 / 0.150 | 0.034 / 0.041 / 0.041 | 0 / 0 |
| fault | GW_A | 12 | 0.127 / 0.162 / 0.162 | 0.055 / 0.091 / 0.091 | 0 / 0 |
| fault | GW_B | 12 | 0.123 / 0.146 / 0.146 | 0.041 / 0.079 / 0.079 | 0 / 0 |
| recovery | GW_A | 38 | 0.135 / 0.190 / 0.204 | 0.051 / 0.090 / 0.096 | 0 / 0 |
| recovery | GW_B | 38 | 0.165 / 0.199 / 0.211 | 0.048 / 0.069 / 0.070 | 0 / 0 |

## Run 5 · native · erp_wan1

Fault window 12.009 s. Recovery window 37.748 s.

| Phase | Flow | OK / total | Failed % | Timeout | Response ms P50 / P95 / max (n) | TCP connect ms P50 / P95 / max (n) | Successful replies by source | Crossed boundary |
| --- | --- | ---: | ---: | ---: | --- | --- | --- | ---: |
| baseline | backup | 21 / 21 | 0.00% | 0 | 1.778 / 2.155 / 2.403 (21) | 0.296 / 0.493 / 0.550 (21) | 198.51.100.1 × 21 | 0 |
| fault | backup | 48 / 48 | 0.00% | 0 | 1.637 / 1.822 / 2.160 (48) | 0.248 / 0.413 / 0.517 (48) | 198.51.100.1 × 48 | 0 |
| recovery | backup | 151 / 151 | 0.00% | 0 | 1.819 / 2.251 / 2.450 (151) | 0.317 / 0.568 / 0.784 (151) | 198.51.100.1 × 151 | 0 |
| baseline | dns | 21 / 21 | 0.00% | 0 | 0.592 / 0.797 / 0.819 (21) | — (0) | — | 0 |
| fault | dns | 48 / 48 | 0.00% | 0 | 0.617 / 0.788 / 0.908 (48) | — (0) | — | 0 |
| recovery | dns | 151 / 151 | 0.00% | 0 | 0.639 / 0.889 / 1.057 (151) | — (0) | — | 0 |
| baseline | erp | 21 / 21 | 0.00% | 0 | 1.779 / 2.083 / 2.117 (21) | 0.319 / 0.455 / 0.508 (21) | 198.51.100.1 × 21 | 0 |
| fault | erp | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp | 151 / 151 | 0.00% | 0 | 1.821 / 2.239 / 2.417 (151) | 0.300 / 0.553 / 0.707 (151) | 198.51.100.1 × 151 | 0 |
| baseline | erp_persistent | 21 / 21 | 0.00% | 0 | 0.329 / 0.542 / 1.754 (21) | 0.181 / 0.181 / 0.181 (1) | 198.51.100.1 × 21 | 0 |
| fault | erp_persistent | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp_persistent | 130 / 151 | 13.91% | 21 | 0.337 / 0.552 / 157.120 (130) | — (0) | 198.51.100.1 × 130 | 0 |

| Time relative to fault or repair | Seconds |
| --- | ---: |
| WAN1 service probe failed | — |
| SD-WAN selected WAN2 | — |
| PF loaded and confirmed WAN2 | — |
| WAN1 service probe recovered | — |
| PF loaded and confirmed WAN1 after repair | — |
| backup first sustained replies after repair | 0.233 / 0.734 s |
| dns first sustained replies after repair | 0.232 / 0.732 s |
| erp first sustained replies after repair | 0.233 / 0.733 s |
| erp_persistent first sustained replies after repair | 5.638 / 5.982 s |

| Phase | Native monitor | Samples | RTT ms P50 / P95 / max | RTT deviation ms P50 / P95 / max | Observed loss % P50 / max |
| --- | --- | ---: | --- | --- | --- |
| baseline | GW_A | 6 | 0.118 / 0.124 / 0.124 | 0.034 / 0.043 / 0.043 | 0 / 0 |
| baseline | GW_B | 6 | 0.127 / 0.196 / 0.196 | 0.052 / 0.058 / 0.058 | 0 / 0 |
| fault | GW_A | 12 | 0.133 / 0.179 / 0.179 | 0.061 / 0.077 / 0.077 | 0 / 0 |
| fault | GW_B | 12 | 0.143 / 0.204 / 0.204 | 0.058 / 0.072 / 0.072 | 0 / 0 |
| recovery | GW_A | 38 | 0.125 / 0.202 / 0.214 | 0.045 / 0.068 / 0.072 | 0 / 0 |
| recovery | GW_B | 38 | 0.136 / 0.199 / 0.200 | 0.046 / 0.132 / 0.141 | 0 / 0 |

## Run 6 · sdwan · erp_wan1

Fault window 12.009 s. Recovery window 37.765 s.

| Phase | Flow | OK / total | Failed % | Timeout | Response ms P50 / P95 / max (n) | TCP connect ms P50 / P95 / max (n) | Successful replies by source | Crossed boundary |
| --- | --- | ---: | ---: | ---: | --- | --- | --- | ---: |
| baseline | backup | 21 / 21 | 0.00% | 0 | 1.823 / 2.102 / 2.192 (21) | 0.268 / 0.440 / 0.486 (21) | 198.51.100.1 × 21 | 0 |
| fault | backup | 48 / 48 | 0.00% | 0 | 1.752 / 2.171 / 2.342 (48) | 0.264 / 0.431 / 0.493 (48) | 198.51.100.1 × 48 | 0 |
| recovery | backup | 151 / 151 | 0.00% | 0 | 1.828 / 2.304 / 2.564 (151) | 0.259 / 0.546 / 1.229 (151) | 198.51.100.1 × 151 | 0 |
| baseline | dns | 21 / 21 | 0.00% | 0 | 0.636 / 0.805 / 0.869 (21) | — (0) | — | 0 |
| fault | dns | 48 / 48 | 0.00% | 0 | 0.641 / 0.795 / 0.833 (48) | — (0) | — | 0 |
| recovery | dns | 151 / 151 | 0.00% | 0 | 0.618 / 0.853 / 2.263 (151) | — (0) | — | 0 |
| baseline | erp | 21 / 21 | 0.00% | 0 | 1.998 / 2.165 / 2.185 (21) | 0.332 / 0.760 / 0.884 (21) | 198.51.100.1 × 21 | 0 |
| fault | erp | 35 / 48 | 27.08% | 13 | 1.777 / 2.154 / 2.343 (35) | 0.237 / 0.398 / 0.474 (35) | 203.0.113.1 × 35 | 0 |
| recovery | erp | 151 / 151 | 0.00% | 0 | 1.843 / 2.237 / 2.431 (151) | 0.267 / 0.526 / 0.809 (151) | 198.51.100.1 × 28 — 203.0.113.1 × 123 | 0 |
| baseline | erp_persistent | 21 / 21 | 0.00% | 0 | 0.349 / 0.600 / 1.862 (21) | 0.451 / 0.451 / 0.451 (1) | 198.51.100.1 × 21 | 0 |
| fault | erp_persistent | 0 / 48 | 100.00% | 48 | — (0) | — (0) | — | 1 |
| recovery | erp_persistent | 130 / 151 | 13.91% | 21 | 0.325 / 0.500 / 1.663 (130) | — (0) | 198.51.100.1 × 130 | 0 |

| Time relative to fault or repair | Seconds |
| --- | ---: |
| WAN1 service probe failed | 3.281 |
| SD-WAN selected WAN2 | 3.281 |
| PF loaded and confirmed WAN2 | 3.321 |
| WAN1 service probe recovered | 0.764 |
| PF loaded and confirmed WAN1 after repair | 30.805 |
| backup first sustained replies after repair | 0.234 / 0.733 s |
| dns first sustained replies after repair | 0.232 / 0.732 s |
| erp first sustained replies after repair | 0.234 / 0.733 s |
| erp_persistent first sustained replies after repair | 5.483 / 5.982 s |

| Phase | Native monitor | Samples | RTT ms P50 / P95 / max | RTT deviation ms P50 / P95 / max | Observed loss % P50 / max |
| --- | --- | ---: | --- | --- | --- |
| baseline | GW_A | 6 | 0.116 / 0.127 / 0.127 | 0.052 / 0.059 / 0.059 | 0 / 0 |
| baseline | GW_B | 6 | 0.168 / 0.183 / 0.183 | 0.061 / 0.077 / 0.077 | 0 / 0 |
| fault | GW_A | 4 | 0.139 / 0.180 / 0.180 | 0.045 / 0.081 / 0.081 | 0 / 0 |
| fault | GW_B | 4 | 0.120 / 0.131 / 0.131 | 0.041 / 0.055 / 0.055 | 0 / 0 |
| recovery | GW_A | 38 | 0.127 / 0.171 / 0.180 | 0.043 / 0.093 / 0.100 | 0 / 0 |
| recovery | GW_B | 38 | 0.124 / 0.193 / 0.206 | 0.042 / 0.062 / 0.068 | 0 / 0 |
