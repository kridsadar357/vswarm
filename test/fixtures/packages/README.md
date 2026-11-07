# Package fixtures (harmless, synthetic)

Small npm and PyPI packages for the package content analysis (`src/sec/content`). Each one imitates a shape from
public write-ups of real incidents, defanged:

| folder | imitates |
|---|---|
| `colors-v1`, `colors-v2` | an account-takeover release (event-stream, ua-parser-js, chalk/debug 2025): v1 is clean, v2 adds a postinstall that reads keys and the environment and posts them out |
| `obfuscated-lib` | a wallet-stealer injected into a library (chalk/debug, September 2025): obfuscated code that decodes and runs itself on import |
| `curl-pipe` | a preinstall that downloads a script and pipes it into a shell (built at test time in `test/content.test.ts`, not kept as a file: Defender deleted it from a Windows checkout) |
| `persist` | a postinstall that adds a login item, a line to `~/.zshrc` and a crontab entry |
| `py-setup` | a PyPI sdist whose `setup.py` decodes and runs code and contacts a raw IP address |
| `py-pth` | a wheel with a `.pth` file that decodes and runs code at every Python start |
| `native-addon`, `binary-fetch`, `aws-like`, `dotenv-like` | legitimate shapes that must not be stopped: node-gyp builds, a postinstall that downloads a prebuilt binary, an SDK that reads its own credentials, a `.env` loader |

Every host is under `example.invalid` (which cannot resolve) or in 203.0.113.0/24 (documentation addresses), every
"payload" decodes to a harmless `console.log` or `print`, and nothing is sent anywhere real. The tests read these
files and pack them into archives in memory; the only time any of them runs is inside the vswarm sandbox.
