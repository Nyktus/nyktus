# Changelog

All notable changes to the Nyktus sensor are documented in this file. The changelog of the server is [CHANGELOG.md](../CHANGELOG.md).

## [0.2.0](https://github.com/Nyktus/nyktus/compare/sensor/v0.1.0...sensor/v0.2.0) (2026-11-11)


### Features

* **honeypots:** record the tool calls of MCP honeypots ([#148](https://github.com/Nyktus/nyktus/issues/148)) ([a20ae39](https://github.com/Nyktus/nyktus/commit/a20ae39f28122f85a50837b3d97fd79233c28ccc))
* **sensor:** emulate a server of the Model Context Protocol ([#149](https://github.com/Nyktus/nyktus/issues/149)) ([8fc8840](https://github.com/Nyktus/nyktus/commit/8fc88402eb1f07a36ad525eaf567e14ea7d777aa))
* **sensor:** let old SSH clients reach the login ([#145](https://github.com/Nyktus/nyktus/issues/145)) ([3b81eb8](https://github.com/Nyktus/nyktus/commit/3b81eb8758a62a3a9b194b63c95d1406c7ef6c7f))
* **sensor:** let the PostgreSQL honeypot speak SCRAM and TLS ([#146](https://github.com/Nyktus/nyktus/issues/146)) ([969d692](https://github.com/Nyktus/nyktus/commit/969d69231393a7811da0d69a752462cf6750639e))


### Bug Fixes

* **sensor:** record a call that the MCP headers refuse ([#151](https://github.com/Nyktus/nyktus/issues/151)) ([2dc3a2f](https://github.com/Nyktus/nyktus/commit/2dc3a2f4e8ea25facd2051d80ce37ec6dc170db1))
* **sensor:** ship the notices of the third-party software ([#139](https://github.com/Nyktus/nyktus/issues/139)) ([484f4af](https://github.com/Nyktus/nyktus/commit/484f4afddeb5c1d2502e944eeb3787f784596738))

## 0.1.0 (2026-11-08)


### Features

* **sensor:** add the sensor with a Telnet honeypot ([#66](https://github.com/Nyktus/nyktus/issues/66)) ([c577b98](https://github.com/Nyktus/nyktus/commit/c577b988faca7cbe1ed4004bd824771ee5699788))
* **sensor:** emulate PostgreSQL and LDAP ([#70](https://github.com/Nyktus/nyktus/issues/70)) ([25f37bb](https://github.com/Nyktus/nyktus/commit/25f37bb92684de1e38963f096569dbb170e2a304))
* **sensor:** emulate SSH ([#68](https://github.com/Nyktus/nyktus/issues/68)) ([f92c98a](https://github.com/Nyktus/nyktus/commit/f92c98acf8fe7206154c5a689d12a46c2967b70e))
* **sensor:** report the version that the release build links ([#116](https://github.com/Nyktus/nyktus/issues/116)) ([184018b](https://github.com/Nyktus/nyktus/commit/184018bbf600444e7df73e34425524b3fd5d0a3b))
* **trigger:** record the sessions and heartbeats of honeypots ([#65](https://github.com/Nyktus/nyktus/issues/65)) ([a5f63cc](https://github.com/Nyktus/nyktus/commit/a5f63ccc25fd60c3ab6a7f903ef0f9f343d07ee5))
