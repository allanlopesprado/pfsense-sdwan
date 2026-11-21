# Offline decision tests for the 40 ms / 30 ms / 5% profile

The test calls the v0.4.28 package's decision and steering functions with synthetic gateway samples and a simulated clock. WAN2 has cost 1 and WAN1 has cost 2. The limits are 40 ms mean RTT, 30 ms RTT standard deviation, and 5% loss. The source files used by the test matched the Git blobs at v0.4.28 (`311ce946ba7ae657de38c93fac5a29d6145553ab`). The run used PHP 8.4.28.

| Output | Expected and observed |
| --- | --- |
| [Threshold cases](threshold-grid.csv) | All 729 passed. WAN2 was selected in 216 cases, WAN1 in 152, and neither was eligible in 361. |
| [Simulated transitions](policy-transitions.csv) | All 14 passed. An ineligible incumbent lost selection on the next decision. An eligible backup stayed in use until the preference had remained healthy for 30 simulated seconds. A missing observation restarted that hold. |
| [Machine-readable totals](summary.json) | Counts, PHP version, source tag, and configured hold. |

For each WAN, the grid uses the three values immediately below, at, and above each tested limit. The loss values are whole percentages, matching dpinger's reported precision. The traffic and PF benchmarks separately measure elapsed forwarding and recovery times.

To reproduce from a Git checkout containing this report, use any PHP 8.4 CLI and a checkout of the v0.4.28 tag.

```sh
git worktree add --detach /tmp/sdwan-0428 v0.4.28
mkdir -p /tmp/sdwan-profile-results
php docs/benchmarks/evidence/ce292-profile-offline/verify.php /tmp/sdwan-0428 /tmp/sdwan-profile-results
```
