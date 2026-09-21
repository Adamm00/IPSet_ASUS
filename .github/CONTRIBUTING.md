<div align="center">

# Contributing to Skynet

**Better protection. Clearer controls. Useful documentation.**

[Project home](../README.md) · [User guide](../docs/README.md) · [Get help](SUPPORT.md) · [Open an issue](https://github.com/Adamm00/IPSet_ASUS/issues/new/choose)

</div>

Bug reports, practical improvements and documentation corrections are welcome. Keep each contribution focused so it is easy to understand and review.

## Choose a starting point

| Contribution | Where to start |
| --- | --- |
| **Something is broken** | Search [existing issues](https://github.com/Adamm00/IPSet_ASUS/issues), then use the [bug report form](https://github.com/Adamm00/IPSet_ASUS/issues/new?template=01-bug-report.yml). Include the exact action, expected result and router versions. |
| **An improvement idea** | Use the [feature request form](https://github.com/Adamm00/IPSet_ASUS/issues/new?template=02-feature-request.yml) to explain the use case. For larger changes, discuss the approach before investing in an implementation. |
| **An unclear instruction** | Edit the relevant guide and open a pull request, or use the [documentation form](https://github.com/Adamm00/IPSet_ASUS/issues/new?template=03-documentation.yml). |
| **Help with your setup** | Start with [troubleshooting](../docs/troubleshooting.md) or the [SNBForums community](https://www.snbforums.com/threads/skynet-v8-router-firewall-security-enhancements.96167/). |

## Working on the code

Fork the repository, create a branch from `master`, and open a pull request against `master`. Explain the problem, the resulting behaviour and how you checked the change.

| File | Responsibility |
| --- | --- |
| [`firewall.sh`](../firewall.sh) | Router service, policy, CLI, updates, storage and diagnostics. |
| [`webui/skynet.asp`](../webui/skynet.asp) | The integrated Asuswrt-Merlin interface. |
| [`filter.list`](../filter.list) | Default threat-feed sources. |
| [`docs/`](../docs/README.md) | Setup, WebUI guide, command reference and troubleshooting. |
| [`assets/screenshots/`](../assets/screenshots) | Public interface previews using illustrative data. |

Follow the surrounding style. The shell script targets **BusyBox `sh`**, and the WebUI runs inside Merlin's router interface. Keep paired backend and WebUI changes together, and preserve supported upgrade and recovery behaviour.

### Check the affected behaviour

For shell changes, run the same check used by CI with ShellCheck 0.11.0:

```sh
shellcheck --norc --shell=busybox firewall.sh
```

Check functional changes on a suitable test router where possible. Include the router model, firmware and commands or WebUI steps you exercised. Be clear about anything you could not verify; do not present untested behaviour as confirmed.

For interface changes, check layout, labels and the affected interaction in the router WebUI. Add screenshots when they help a reviewer understand the change, using fictional or redacted data.

## Writing and screenshots

Keep instructions direct and consistent with the current interface. Update the relevant guide when behaviour changes, and preserve existing heading links where possible. The versioned `docs/` pages hold the detailed instructions; the wiki links readers to them.

Check relative links, code examples and GitHub's rendered preview. Public screenshots should use illustrative data, with no real network details or credentials. There is no application build step for documentation-only changes.
