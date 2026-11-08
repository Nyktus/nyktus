# Changelog

All notable changes to the Nyktus server are documented in this file. The sensor has a changelog of its own in [sensor/CHANGELOG.md](sensor/CHANGELOG.md).

## [0.2.0](https://github.com/Nyktus/nyktus/compare/v0.1.0...v0.2.0) (2026-11-08)


### Features

* **deploy:** add a script that sets up the database and the logins ([#137](https://github.com/Nyktus/nyktus/issues/137)) ([fd9204f](https://github.com/Nyktus/nyktus/commit/fd9204fc57fc1c812c711dc92657e0ce431d6690))
* **web:** show the QR code of a honeytoken URL on request ([#136](https://github.com/Nyktus/nyktus/issues/136)) ([f2c63c6](https://github.com/Nyktus/nyktus/commit/f2c63c612ad053841ba8f1c6125d6f91021bbbae))


### Bug Fixes

* **catalog:** use the German terms in the lists and name the working update command ([#133](https://github.com/Nyktus/nyktus/issues/133)) ([da573ca](https://github.com/Nyktus/nyktus/commit/da573ca05a1f162667c8ed67a1f34ae3c0e1758a))
* **config:** reject an international host name in the URLs of the console and the trigger ([#134](https://github.com/Nyktus/nyktus/issues/134)) ([7893fbb](https://github.com/Nyktus/nyktus/commit/7893fbb6d64359780bcd71497ba70222d5c9863d))

## 0.1.0 (2026-11-08)


### Features

* **alerting:** deliver alerts by email ([#44](https://github.com/Nyktus/nyktus/issues/44)) ([6aa1db3](https://github.com/Nyktus/nyktus/commit/6aa1db31a27cad8da24714e7218a90bff0fa84de))
* **alerting:** deliver alerts to channels ([#35](https://github.com/Nyktus/nyktus/issues/35)) ([e4e9710](https://github.com/Nyktus/nyktus/commit/e4e9710f1c2790379f6eec1b1ef5e2a24b3ce17c))
* **alerting:** format alerts for Slack and Teams ([#36](https://github.com/Nyktus/nyktus/issues/36)) ([bc6c459](https://github.com/Nyktus/nyktus/commit/bc6c45957b30f3a26c91b3e190efadb1484967f1))
* **alerting:** manage alert channels ([#34](https://github.com/Nyktus/nyktus/issues/34)) ([8a99a7d](https://github.com/Nyktus/nyktus/commit/8a99a7d12a9d849914df6dee456dd44918875103))
* **api:** add the OpenAPI contract and route authorization ([#1](https://github.com/Nyktus/nyktus/issues/1)) ([a2788bb](https://github.com/Nyktus/nyktus/commit/a2788bb720fd31a7d4cdfb8b633e08b6c5b194df))
* **api:** assign a scenario when creating honeytokens and honeypots ([#106](https://github.com/Nyktus/nyktus/issues/106)) ([ee521c1](https://github.com/Nyktus/nyktus/commit/ee521c16991ab7ab8e88298a7f66932e1201d6ef))
* **artifact:** download artifacts and keep their placement notes ([#59](https://github.com/Nyktus/nyktus/issues/59)) ([6b97868](https://github.com/Nyktus/nyktus/commit/6b9786846077b691c2e2254faa8ef5cb70285b49))
* **audit:** list audit entries for administrators ([#9](https://github.com/Nyktus/nyktus/issues/9)) ([4cfdb94](https://github.com/Nyktus/nyktus/commit/4cfdb9470fbd1ac9e65c20fe6334eda6336a4d15))
* **audit:** record security-relevant actions ([#3](https://github.com/Nyktus/nyktus/issues/3)) ([b81cedd](https://github.com/Nyktus/nyktus/commit/b81cedd9bfe460c346261ba5a60341a7e01621b7))
* **auth:** add optional TOTP with recovery codes ([#16](https://github.com/Nyktus/nyktus/issues/16)) ([3fb1976](https://github.com/Nyktus/nyktus/commit/3fb1976b8aeba9c45c2781b0b50bc2cae12aacad))
* **auth:** change and reset passwords ([#14](https://github.com/Nyktus/nyktus/issues/14)) ([be30957](https://github.com/Nyktus/nyktus/commit/be30957b67f9c0a52c95f4d07102de428144d083))
* **auth:** confirm sensitive actions through the identity provider ([#24](https://github.com/Nyktus/nyktus/issues/24)) ([ac1d7f4](https://github.com/Nyktus/nyktus/commit/ac1d7f47485139e7f4ed8ca69a7f7d90aa550d9a))
* **auth:** create the first administrator through a setup token ([#6](https://github.com/Nyktus/nyktus/issues/6)) ([dfde71d](https://github.com/Nyktus/nyktus/commit/dfde71dfd933fd77428018c9d653d531f8985f28))
* **auth:** issue scoped API keys ([#18](https://github.com/Nyktus/nyktus/issues/18)) ([bd13b22](https://github.com/Nyktus/nyktus/commit/bd13b22e41ed68b2b54282b7afb21a28e48f9c30))
* **auth:** manage users with activation links ([#11](https://github.com/Nyktus/nyktus/issues/11)) ([47ceb28](https://github.com/Nyktus/nyktus/commit/47ceb284e955fba62c86f0a502ca25efb82f7675))
* **auth:** sign in through OpenID Connect ([#23](https://github.com/Nyktus/nyktus/issues/23)) ([7809ac3](https://github.com/Nyktus/nyktus/commit/7809ac3720011eb2ce0cb2628b1c2be56d9af399))
* **auth:** sign in with server-side sessions ([#8](https://github.com/Nyktus/nyktus/issues/8)) ([8e83268](https://github.com/Nyktus/nyktus/commit/8e832685c14057f1535aee0477f237af41907b13))
* **auth:** store users with Argon2id password hashes ([#2](https://github.com/Nyktus/nyktus/issues/2)) ([8944813](https://github.com/Nyktus/nyktus/commit/8944813c7d9654b36653f5e3517fedd427025185))
* **catalog:** add Active Directory decoy accounts ([#101](https://github.com/Nyktus/nyktus/issues/101)) ([7df74ca](https://github.com/Nyktus/nyktus/commit/7df74ca28a6fcdcb859353aba6a53eeb56eebcea))
* **catalog:** add cloud deceptions ([#103](https://github.com/Nyktus/nyktus/issues/103)) ([1d85a50](https://github.com/Nyktus/nyktus/commit/1d85a50caae7739c0cb7c4cde7ba4ad7802ca7f8))
* **catalog:** add more deceptions ([#93](https://github.com/Nyktus/nyktus/issues/93)) ([3cd5941](https://github.com/Nyktus/nyktus/commit/3cd594196dfabeaa907cf01339f4dbd7f54fa035))
* **catalog:** add pocket litter and further lures ([#100](https://github.com/Nyktus/nyktus/issues/100)) ([0cb1bc8](https://github.com/Nyktus/nyktus/commit/0cb1bc8959ff98df625f904b44b8d2f1d513165f))
* **catalog:** add the category cloud ([#102](https://github.com/Nyktus/nyktus/issues/102)) ([3cf68a8](https://github.com/Nyktus/nyktus/commit/3cf68a8ba8b2018bc9bf5629f9b99013fe38ab39))
* **catalog:** add the first deceptions ([#51](https://github.com/Nyktus/nyktus/issues/51)) ([2a3cc97](https://github.com/Nyktus/nyktus/commit/2a3cc97e66a6613885cded093a00e37cb6086e15))
* **catalog:** list the deceptions of the catalog ([#50](https://github.com/Nyktus/nyktus/issues/50)) ([9a06db6](https://github.com/Nyktus/nyktus/commit/9a06db69a0f7bb890783629acf1e24a98092f9de))
* **catalog:** load and validate the deception catalog ([#49](https://github.com/Nyktus/nyktus/issues/49)) ([503e9bd](https://github.com/Nyktus/nyktus/commit/503e9bd608d0d0c7adcaecb8412223476e3b42c2))
* **catalog:** publish the catalog as a generated JSON file ([#60](https://github.com/Nyktus/nyktus/issues/60)) ([6b142f0](https://github.com/Nyktus/nyktus/commit/6b142f0570ae68ef3540192e77d71d59f8f5102c))
* **catalog:** render artifacts with a restricted template engine ([#48](https://github.com/Nyktus/nyktus/issues/48)) ([1e1450e](https://github.com/Nyktus/nyktus/commit/1e1450e5410e4e4a4258d3a3b7af578de1860da2))
* **console:** expose metrics ([#40](https://github.com/Nyktus/nyktus/issues/40)) ([90ba918](https://github.com/Nyktus/nyktus/commit/90ba91811c595a3956867e187d6a22d3a1bb5dfb))
* **deploy:** add a development environment with Docker Compose ([#88](https://github.com/Nyktus/nyktus/issues/88)) ([75d9cce](https://github.com/Nyktus/nyktus/commit/75d9cce30d9e41e6760956abbe67664bec4045a9))
* **dns:** record lookups of DNS honeytokens ([#28](https://github.com/Nyktus/nyktus/issues/28)) ([13a0987](https://github.com/Nyktus/nyktus/commit/13a0987840982464c4f91444a4c819f254df57e9))
* **engage:** embed the activities of MITRE Engage ([#47](https://github.com/Nyktus/nyktus/issues/47)) ([01679ef](https://github.com/Nyktus/nyktus/commit/01679ef45ff0c8e3ce724fdc962aaa480f9e5ef0))
* **honeypot:** keep the secret of a honeypot readable ([#107](https://github.com/Nyktus/nyktus/issues/107)) ([5f2a78a](https://github.com/Nyktus/nyktus/commit/5f2a78a7aa5e8e78ff4e366f6c21e48bdff6a0be))
* **honeypot:** manage honeypots ([#64](https://github.com/Nyktus/nyktus/issues/64)) ([8939332](https://github.com/Nyktus/nyktus/commit/8939332e9dd828c01492c12e0eadda9e9049718f))
* **honeytoken:** manage honeytokens ([#25](https://github.com/Nyktus/nyktus/issues/25)) ([bac19c2](https://github.com/Nyktus/nyktus/commit/bac19c227e0a8645f5930ff85c2619d3f8b3d2ac))
* **honeytoken:** set the severity of each honeytoken ([#56](https://github.com/Nyktus/nyktus/issues/56)) ([a772ec5](https://github.com/Nyktus/nyktus/commit/a772ec53efa526b5f8a18022843e0729991c6088))
* **http:** record the client address and principal in the access log ([#7](https://github.com/Nyktus/nyktus/issues/7)) ([0d90d1f](https://github.com/Nyktus/nyktus/commit/0d90d1fa361eb328b339fff4c7fea2630b09ad72))
* **http:** resolve the client address behind trusted proxies ([#5](https://github.com/Nyktus/nyktus/issues/5)) ([ac69727](https://github.com/Nyktus/nyktus/commit/ac697271d8b07252eeeb0c7fc6dc6a853fc36df1))
* **incident:** correlate events into incidents ([#29](https://github.com/Nyktus/nyktus/issues/29)) ([cf70d2a](https://github.com/Nyktus/nyktus/commit/cf70d2a1e4d8d28ea21eaf91abe62f0917eb517a))
* **incident:** correlate the events of a scenario in one incident ([#55](https://github.com/Nyktus/nyktus/issues/55)) ([87be375](https://github.com/Nyktus/nyktus/commit/87be3751e7c326527902f1f33f1a8d20ac3afc3f))
* **incident:** name the resource of an incident ([#89](https://github.com/Nyktus/nyktus/issues/89)) ([0072a7a](https://github.com/Nyktus/nyktus/commit/0072a7a8a57274a36a71f2210fb8426f782f602d))
* **incident:** read and triage incidents ([#31](https://github.com/Nyktus/nyktus/issues/31)) ([7eb13d9](https://github.com/Nyktus/nyktus/commit/7eb13d9090189352d29d39ee9c5a904800c95500))
* **platform:** encrypt secrets at rest with AES-256-GCM ([#15](https://github.com/Nyktus/nyktus/issues/15)) ([4ce3312](https://github.com/Nyktus/nyktus/commit/4ce331226df4226968cc5115243d31f0c81ee74e))
* **scenario:** apply a deception of the catalog ([#57](https://github.com/Nyktus/nyktus/issues/57)) ([5255d78](https://github.com/Nyktus/nyktus/commit/5255d78920d5a4b4850881580096522740f2c9b4))
* **scenario:** hold several deceptions and add artifacts later ([#97](https://github.com/Nyktus/nyktus/issues/97)) ([3168b06](https://github.com/Nyktus/nyktus/commit/3168b0628abcbbc71679d31139d03e096fc1e034))
* **scenario:** manage scenarios and assign honeytokens to them ([#54](https://github.com/Nyktus/nyktus/issues/54)) ([c6fa011](https://github.com/Nyktus/nyktus/commit/c6fa011737f7de2934d586ad8b857d5d21acff15))
* **sensor:** add the sensor with a Telnet honeypot ([#66](https://github.com/Nyktus/nyktus/issues/66)) ([c577b98](https://github.com/Nyktus/nyktus/commit/c577b988faca7cbe1ed4004bd824771ee5699788))
* **sensor:** emulate PostgreSQL and LDAP ([#70](https://github.com/Nyktus/nyktus/issues/70)) ([25f37bb](https://github.com/Nyktus/nyktus/commit/25f37bb92684de1e38963f096569dbb170e2a304))
* **sensor:** emulate SSH ([#68](https://github.com/Nyktus/nyktus/issues/68)) ([f92c98a](https://github.com/Nyktus/nyktus/commit/f92c98acf8fe7206154c5a689d12a46c2967b70e))
* **ssrf:** guard requests to user-supplied URLs ([#33](https://github.com/Nyktus/nyktus/issues/33)) ([59cc94c](https://github.com/Nyktus/nyktus/commit/59cc94c948fd256aacd0e3358722a958c705cf47))
* **trigger:** record POST requests of honeytokens ([#94](https://github.com/Nyktus/nyktus/issues/94)) ([31ccd1b](https://github.com/Nyktus/nyktus/commit/31ccd1bb593fbd5a34df0d49590b64a1d3a68526))
* **trigger:** record requests of honeytokens ([#26](https://github.com/Nyktus/nyktus/issues/26)) ([c5a98b5](https://github.com/Nyktus/nyktus/commit/c5a98b55c41da2a98859237735c4bc9be22e63d3))
* **trigger:** record the sessions and heartbeats of honeypots ([#65](https://github.com/Nyktus/nyktus/issues/65)) ([a5f63cc](https://github.com/Nyktus/nyktus/commit/a5f63ccc25fd60c3ab6a7f903ef0f9f343d07ee5))
* **web:** add sign-in and the one-time pages to the web console ([#73](https://github.com/Nyktus/nyktus/issues/73)) ([3829263](https://github.com/Nyktus/nyktus/commit/3829263255450b2b826b6ef74dcdefb051a83b9c))
* **web:** apply deceptions with artifacts and extend scenarios ([#98](https://github.com/Nyktus/nyktus/issues/98)) ([46d036d](https://github.com/Nyktus/nyktus/commit/46d036d00481fce391f2d7e309af68638d8dc8cc))
* **web:** group the navigation of the frame ([#81](https://github.com/Nyktus/nyktus/issues/81)) ([24df324](https://github.com/Nyktus/nyktus/commit/24df324f2cd67994cad211990a6024fad154aa46))
* **web:** guide scenarios by what a deception asks for ([#109](https://github.com/Nyktus/nyktus/issues/109)) ([db6bf9f](https://github.com/Nyktus/nyktus/commit/db6bf9f08d3861d95b0116f0925d2f5a5e478e8a))
* **web:** manage alert channels and accounts in the web console ([#87](https://github.com/Nyktus/nyktus/issues/87)) ([47ecc9d](https://github.com/Nyktus/nyktus/commit/47ecc9df6ad81206dcbfb4af084f054664e6674d))
* **web:** manage API keys in the web console ([#79](https://github.com/Nyktus/nyktus/issues/79)) ([da1d8c1](https://github.com/Nyktus/nyktus/commit/da1d8c1810e6003dd5f8eacfe3a20c4592ec5cce))
* **web:** manage honeypots and scenarios in the web console ([#75](https://github.com/Nyktus/nyktus/issues/75)) ([3574732](https://github.com/Nyktus/nyktus/commit/3574732e19d8e13cd546475aac925855d6838367))
* **web:** manage honeytokens in the web console ([#85](https://github.com/Nyktus/nyktus/issues/85)) ([723c2e4](https://github.com/Nyktus/nyktus/commit/723c2e4db38113b9a2971d7d4e7e752d14aa8e17))
* **web:** manage the account, and show the audit log and the metrics ([#80](https://github.com/Nyktus/nyktus/issues/80)) ([6f52642](https://github.com/Nyktus/nyktus/commit/6f52642961c7632df32c3b2ac94ddb8a1b56ee9c))
* **web:** report the forms of sign-in and generate the API types ([#71](https://github.com/Nyktus/nyktus/issues/71)) ([9ae2bc4](https://github.com/Nyktus/nyktus/commit/9ae2bc4a6ac17176926da5643d737988b2b3dbf6))
* **web:** serve an embedded web console ([#72](https://github.com/Nyktus/nyktus/issues/72)) ([86649ce](https://github.com/Nyktus/nyktus/commit/86649ce450ef722756eee4e640c511940c90e319))
* **web:** show an overview and rework the navigation ([#91](https://github.com/Nyktus/nyktus/issues/91)) ([ba06fc2](https://github.com/Nyktus/nyktus/commit/ba06fc275220ae4e320773db56cde4faae27d524))
* **web:** show the catalog and manage artifacts in the web console ([#86](https://github.com/Nyktus/nyktus/issues/86)) ([7428080](https://github.com/Nyktus/nyktus/commit/7428080f09981f45de2439d7afcd251e2cab4048))
* **web:** triage incidents in the web console ([#77](https://github.com/Nyktus/nyktus/issues/77)) ([f96e416](https://github.com/Nyktus/nyktus/commit/f96e416ff8d11c5d0560faf0b6feae894c9cc317))
* **worker:** close inactive incidents ([#39](https://github.com/Nyktus/nyktus/issues/39)) ([488f41c](https://github.com/Nyktus/nyktus/commit/488f41c97b930003431065eb856dddaca2cea77b))
* **worker:** delete audit entries and incident data after their retention ([#38](https://github.com/Nyktus/nyktus/issues/38)) ([5c55536](https://github.com/Nyktus/nyktus/commit/5c555365aab57be660107e365552085032d1f013))
* **worker:** run periodic tasks and remove expired rows ([#37](https://github.com/Nyktus/nyktus/issues/37)) ([0fcbf76](https://github.com/Nyktus/nyktus/commit/0fcbf760c862d629135dd745cf3d6bae5ffabac2))
* **worker:** send mail over SMTP ([#43](https://github.com/Nyktus/nyktus/issues/43)) ([ab5265b](https://github.com/Nyktus/nyktus/commit/ab5265b2abe29a95202e4b923a65def7455e5df8))


### Bug Fixes

* **db:** revoke default privileges before granting on users ([#4](https://github.com/Nyktus/nyktus/issues/4)) ([a6f3a40](https://github.com/Nyktus/nyktus/commit/a6f3a4036f37bd1b0763d0776e4e108913c49324))
* **incident:** wait for the session that broke off before postponing its job ([#128](https://github.com/Nyktus/nyktus/issues/128)) ([00f1471](https://github.com/Nyktus/nyktus/commit/00f1471907f9ac7563d16348c717c11435ed570d))
* **session:** record a new session as last seen when it was created ([#30](https://github.com/Nyktus/nyktus/issues/30)) ([6253638](https://github.com/Nyktus/nyktus/commit/62536387463bec13d67f3548aee2f040a7a0ae7c))
* **test:** confirm TOTP factors with a code that survives a step change ([#19](https://github.com/Nyktus/nyktus/issues/19)) ([444f565](https://github.com/Nyktus/nyktus/commit/444f565123f7196de753f1f91e4dee4a3b5d19b8))
* **trigger:** replace characters that reorder or hide text in event headers ([#61](https://github.com/Nyktus/nyktus/issues/61)) ([4a6e114](https://github.com/Nyktus/nyktus/commit/4a6e114c44b3fd078b9f421f0f0e9d45f6b166c7))
* **web:** revise console texts, password manager support and honeypot flow ([#104](https://github.com/Nyktus/nyktus/issues/104)) ([eb8dace](https://github.com/Nyktus/nyktus/commit/eb8dace2a3beb31a59ed09b6d7f010773f243c58))
