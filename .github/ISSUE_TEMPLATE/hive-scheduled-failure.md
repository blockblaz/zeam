---
title: "Daily Hive run failed: {{ env.SIMULATOR }} / {{ env.DEVNET }}"
labels: ci-failure, hive
---

The scheduled Hive CI run failed.

| Field | Value |
|---|---|
| Simulator | `{{ env.SIMULATOR }}` |
| Devnet profile | `{{ env.DEVNET }}` |
| Hive source | `{{ env.HIVE_REPOSITORY }}@{{ env.HIVE_VERSION }}` |
| Commit tested | [`{{ env.COMMIT_SHA }}`]({{ env.COMMIT_URL }}) |
| Workflow run | [#{{ env.GITHUB_RUN_ID }}]({{ env.RUN_URL }}) |

This issue is auto-opened by the `hive` workflow and updated in place by later scheduled failures; close it once the underlying cause is fixed and the next daily run goes green.

### Notes

- The upstream `clients/zeam` Dockerfile in `ethereum/hive` selects the devnet4
  binary from the pre-published `blockblaz/zeam:devnet4` image (no tag build
  arg), so a failure here may reflect the published image rather than HEAD of
  `main`. Check the published image tag before assuming a regression in-tree.
- Logs, per-test results, and the hiveview output are attached to the workflow
  run as artifacts (`hive-zeam-{{ env.DEVNET }}-*`).
