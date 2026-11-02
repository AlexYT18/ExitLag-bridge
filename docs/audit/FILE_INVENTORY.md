# Baseline tracked-file inventory

Source commit: `c0525a74c35fd74c815326d957c21a593a6aaccb`. Generated from `git ls-tree` and exact committed blob contents; untracked audit notes and later changes are excluded. All 185 baseline tracked files were assigned for source/document review. Binary site assets were classified by metadata, not treated as executable code. Line references in subsystem notes refer to this baseline.

## Subsystem counts

| Subsystem | Files |
| --- | ---: |
| CI and contribution | 6 |
| Discovery and operations | 14 |
| Documentation and site | 29 |
| Installers | 13 |
| Licensing | 28 |
| Linux backend | 11 |
| Repository metadata | 4 |
| Validation | 33 |
| Windows compatibility | 10 |
| Wine compatibility | 2 |
| macOS preserved | 35 |

## Every tracked file

Size is bytes; lines are split text lines or `binary`. SHA256 allows reproducing the snapshot without recording runtime/private data.

| File | Subsystem | Purpose | Bytes | Lines | SHA256 |
| --- | --- | --- | ---: | ---: | --- |
| `.gitattributes` | Repository metadata | Source attributes | 289 | 6 | `e4fdc36ddbacc1bdccb8b9c4042c04a05302d0b16d107a7ad51d1c7007dfa9a1` |
| `.github/ISSUE_TEMPLATE/game-compatibility.yml` | CI and contribution | Issue/PR template | 1289 | 43 | `0a3a8eed9fa9d89097da7d5ae3205f22d4298e0058291b204a213bfe9d78c6b8` |
| `.github/pull_request_template.md` | CI and contribution | Issue/PR template | 464 | 12 | `18a8ac73e95a4e48d7f2f027c6fb280fa28af85219404aa87e2e2a5804daf725` |
| `.github/workflows/installer-validation.yml` | CI and contribution | Workflow | 4452 | 97 | `ac7cfc83fd92ae4358611f51702b95ff8b55c013b851040ca20137e73f0f1e7b` |
| `.github/workflows/linux-portable-compatibility.yml` | CI and contribution | Workflow | 3953 | 79 | `10458d52e7f457e32e9f473bb9d6788f3341ca3aed49d0fd09e46e4941a40b20` |
| `.github/workflows/source-privacy.yml` | CI and contribution | Workflow | 455 | 19 | `fa7cb44087b476a3a5723e8eb167ccbcbc200ab4e5168549285f9c54dbfeb959` |
| `.github/workflows/ubuntu-package-compatibility.yml` | CI and contribution | Workflow | 2485 | 51 | `5ba73ede6f999dd4eb0786421987bcb767b64cc0025ec0c45c6894b2f8daea62` |
| `.gitignore` | Repository metadata | Generated/private artifact exclusions | 1634 | 80 | `4125b7efbdedc92ba171b91c42675d458d3a2bb9588a16827eab1b9461d02fe3` |
| `CONTRIBUTING.md` | Repository metadata | Contribution, privacy and validation policy | 1892 | 19 | `eab59368d7263d920e43ca993877dcc0db8e09420c3043a33bc1bacf31608dae` |
| `LICENSE` | Licensing | First-party GPL-3.0 license | 35149 | 674 | `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986` |
| `LICENSES/LGPL-2.1.txt` | Licensing | Third-party license/provenance notice | 26434 | 502 | `e237fa56668030e928551ddd60f05df5fe957f75eab874bbd017e085ed722e7c` |
| `LICENSES/README.md` | Licensing | Third-party license/provenance notice | 586 | 12 | `6691109ab5da77ff27ff025f8f485d9310e123408ae81d81ac178ee33ee64682` |
| `LICENSES/Zig-MIT.txt` | Licensing | Third-party license/provenance notice | 1080 | 21 | `5c537d6853e005298a285d508cff9ac7192cea23576c840d485b2b586a7ff177` |
| `LICENSES/python-standalone/LICENSE` | Licensing | Third-party license/provenance notice | 16725 | 373 | `1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5` |
| `LICENSES/python-standalone/LICENSE.bdb.txt` | Licensing | Third-party license/provenance notice | 7293 | 126 | `3bdff06e69991c94664f2ef5c5f8096f60b7dbec071756ea6cc26b445e06ec5b` |
| `LICENSES/python-standalone/LICENSE.bzip2.txt` | Licensing | Third-party license/provenance notice | 1743 | 37 | `1f38bbc7caacafd65169276d759c0d88c991b753b643ce35d0e45ea1971dd441` |
| `LICENSES/python-standalone/LICENSE.cpython.txt` | Licensing | Third-party license/provenance notice | 36164 | 771 | `86e61415828a8b5b06ec8d024e6f086ce155a8b85fd0c419c0ba4dc004e74fdd` |
| `LICENSES/python-standalone/LICENSE.expat.txt` | Licensing | Third-party license/provenance notice | 1144 | 21 | `122f2c27000472a201d337b9b31f7eb2b52d091b02857061a8880371612d9534` |
| `LICENSES/python-standalone/LICENSE.libX11.txt` | Licensing | Third-party license/provenance notice | 47018 | 942 | `2daec087a88e7c9b8082557cdeebad5bbb8155a4137472f0b22e269cd99d0c1e` |
| `LICENSES/python-standalone/LICENSE.libXau.txt` | Licensing | Third-party license/provenance notice | 1148 | 21 | `56abe29bb1d9806a9e04fa9f80fed2c0f18027594df3f098148d814aef6bddfa` |
| `LICENSES/python-standalone/LICENSE.libedit.txt` | Licensing | Third-party license/provenance notice | 1614 | 29 | `29cea33c32bbc9785142386377915612a2fa786482c46843383384aded2e09b1` |
| `LICENSES/python-standalone/LICENSE.libffi.txt` | Licensing | Third-party license/provenance notice | 1132 | 21 | `deaf3a42effb551a5b140fa9afefed183a27f1341c6d1bf430d106a5e6931fc0` |
| `LICENSES/python-standalone/LICENSE.liblzma.txt` | Licensing | Third-party license/provenance notice | 660 | 13 | `9a4062de0a2c388a98cf35a35d348b62fa97c838a71c3c28ee1a2d7d0a565b02` |
| `LICENSES/python-standalone/LICENSE.libuuid.txt` | Licensing | Third-party license/provenance notice | 1432 | 27 | `122ee1f7e258f2c3c0e538a75c037684f420454bf3850ddc74ce750bbf5fe86b` |
| `LICENSES/python-standalone/LICENSE.libxcb.txt` | Licensing | Third-party license/provenance notice | 1337 | 30 | `c5ffbfeaa501071ceeb97b7de2c0d703fdaa35de01c0fb6cbac1c28453a3e9fd` |
| `LICENSES/python-standalone/LICENSE.mpdecimal.txt` | Licensing | Third-party license/provenance notice | 1284 | 24 | `669512af7219f58be03a398766d7c9da11a3b3df9d3f05cb74c5ceca25c8da3b` |
| `LICENSES/python-standalone/LICENSE.ncurses.txt` | Licensing | Third-party license/provenance notice | 1447 | 29 | `87a4c4442337b8968ef956031c406b74f9cb7149b7ba87311bdaba534816201c` |
| `LICENSES/python-standalone/LICENSE.openssl-3.txt` | Licensing | Third-party license/provenance notice | 10175 | 177 | `7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a` |
| `LICENSES/python-standalone/LICENSE.sqlite.txt` | Licensing | Third-party license/provenance notice | 1481 | 23 | `38bef3d28b24f145ea293bd3b6eb4b20396982abc8303128fb493986ea5bc719` |
| `LICENSES/python-standalone/LICENSE.tcl.txt` | Licensing | Third-party license/provenance notice | 2255 | 40 | `c0a69a2bfd757361ec7e6143973b103c90409316b49e9c88db26ad6388e79f16` |
| `LICENSES/python-standalone/LICENSE.tix.txt` | Licensing | Third-party license/provenance notice | 2826 | 54 | `3ac5cdd0bef6c43ce34c6a7ced452081d9e5a0bf94082b9f9147d23ec9e214f5` |
| `LICENSES/python-standalone/LICENSE.zlib-ng.txt` | Licensing | Third-party license/provenance notice | 867 | 19 | `6c9f0d975b41afaa34d22f55bb8986ce69e5cb7ad327cb2b28820cd425edf5ee` |
| `LICENSES/python-standalone/LICENSE.zlib.txt` | Licensing | Third-party license/provenance notice | 995 | 21 | `818922b2620f12801a12bf78e399644a30990e66824abd8ca8ec24d451d6f92c` |
| `LICENSES/python-standalone/LICENSE.zstd.txt` | Licensing | Third-party license/provenance notice | 1549 | 30 | `7055266497633c9025b777c78eb7235af13922117480ed5c674677adc381c9d8` |
| `LICENSES/python-standalone/PROVENANCE.txt` | Licensing | Third-party license/provenance notice | 280 | 4 | `38abf0d12437c85f5e3ba06d0fb1b776e65db1bc12141d92f1b282ab95eeff56` |
| `LICENSES/python-standalone/python-licenses.rst` | Licensing | Third-party license/provenance notice | 105875 | 2083 | `e43fb936c6655d7996dba480d7ebdea492d6040ec388eb8ed9d1000f72de8cab` |
| `README.md` | Repository metadata | Public overview and quick start | 14468 | 284 | `8cd571bf75361be3924dc213b63209fa4a0274a3f71f442986d09083046eb820` |
| `THIRD_PARTY.md` | Licensing | Third-party license/provenance notice | 5780 | 108 | `e215cce20a9bf3d5d4931c14422d453a011fa6b95332c8daa566e02c12097e3c` |
| `backend/Makefile` | Linux backend | Native daemon build | 176 | 10 | `ffaa6c65a664f6c62a24ed0968d2ac6f55c5a14296a71d1cb2d54c967be7282c` |
| `backend/exitlag-netd.c` | Linux backend | NFQUEUE/IPC/process attribution/TCP and restricted UDP daemon | 103907 | 2293 | `69d2be7f1a9896fcbe1bdb5376ff06a1460cda22b7492387fa00132e49d0bf02` |
| `backend/identity-map.example` | Linux backend | Explicit identity-map format and examples | 1270 | 21 | `a22138cc7cd83cb78d9d2cf8d93ae70d3e9b028d9d4803b2372372865a18954a` |
| `backend/nft-setup.sh` | Linux backend | Firewall/session lifecycle shell helper: nft-setup | 6903 | 172 | `0e7a32c12a6e7131cf0070262c2ce0c559f9b82b175a675ca1e93e0dc05e39bc` |
| `backend/nft-teardown.sh` | Linux backend | Firewall/session lifecycle shell helper: nft-teardown | 387 | 13 | `392a1cf14f7ba27424e86aad6ad06a23399a99491ae3a3d2cef6a600dae541e3` |
| `backend/protocol.h` | Linux backend | Packed v3 IPC wire contract | 8742 | 235 | `fecc7c3a711068dd1e0168a3769ef8de420f83a46c6020458b6e7951b887e982` |
| `backend/run-passive.sh` | Linux backend | Firewall/session lifecycle shell helper: run-passive | 2247 | 57 | `779aa6f5353dd86fc0ab5c8b8ae74525edf0b9bcd95aecd894a52e7a94911bb7` |
| `backend/run-tcp-redirect.sh` | Linux backend | Firewall/session lifecycle shell helper: run-tcp-redirect | 3100 | 70 | `a90f93b5e7c3f1fc568d9caf931a63f17f1d49b742b8e951de9903f06e570383` |
| `backend/run-udp-observe.sh` | Linux backend | Firewall/session lifecycle shell helper: run-udp-observe | 3491 | 78 | `aaa28d5467ca3a8304856fe344c3db24bf4bb66888ed5b717413e27dbedc24a2` |
| `backend/run-udp-steer.sh` | Linux backend | Firewall/session lifecycle shell helper: run-udp-steer | 4002 | 84 | `9d85606f8c726b8928992df86c7283219e429d2e8f893a32ce84c78d9539abe5` |
| `backend/runtime-guard.sh` | Linux backend | Firewall/session lifecycle shell helper: runtime-guard | 4555 | 122 | `ab813361dc0596131f1295f791bb3fb752fe487d184f33553c09680a32530335` |
| `docs/.nojekyll` | Documentation and site | Technical/user documentation: .nojekyll | 0 | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `docs/arch-linux.md` | Documentation and site | Technical/user documentation: arch-linux.md | 3015 | 67 | `83325f85a70f551b4bdaf6729b433189fc54533603f41c49c0d969b015150e42` |
| `docs/architecture.md` | Documentation and site | Technical/user documentation: architecture.md | 12001 | 250 | `4930c36c72c18aeff90bffba0f8e42a1bc46fe2aa0653db5cd6e8dad04a07c6e` |
| `docs/compatibility.md` | Documentation and site | Technical/user documentation: compatibility.md | 3030 | 44 | `13ddc45ec6a93a030736f5ba22028ecb422ae05b72858ba00449561f5c6487aa` |
| `docs/exitlag-updates.md` | Documentation and site | Technical/user documentation: exitlag-updates.md | 4152 | 97 | `91cbea720aa1b0b8a3065c7f78743c25f5bc61c96c16177b9d7a6ce07a38bef0` |
| `docs/external-process-routing.md` | Documentation and site | Technical/user documentation: external-process-routing.md | 1021 | 18 | `437419c08884b82dfff44a350b5599ba389bb49ced9b0c8a353eedd48ddbdc8d` |
| `docs/faq.md` | Documentation and site | Technical/user documentation: faq.md | 5555 | 101 | `90a4d157df1602178ee60fbfbc5dc0349cda37a305b68b815afd56dfbd34d941` |
| `docs/favicon.svg` | Documentation and site | Static asset | 385 | 5 | `e0728d79d577c3f2f04929f977e2e34f406e0b03c181fc013fc28f9886b8aed1` |
| `docs/index.html` | Documentation and site | Technical/user documentation: index.html | 14781 | 128 | `620fd5c110474df9ca5ad615f24e783c32a21253354568b063a76c19fdddefb9` |
| `docs/ipv6-active-rewrite.md` | Documentation and site | Technical/user documentation: ipv6-active-rewrite.md | 4017 | 92 | `ccd8eb408b2ec45bb0d6b700bd7a45d1422eda6e5e3619457b830b376810ef41` |
| `docs/linux.md` | Documentation and site | Technical/user documentation: linux.md | 4067 | 87 | `1cbb82462d92fa4c519883691ff181e7fc98f0ee987dec9e3840d4dcc4a0e1fa` |
| `docs/llms.txt` | Documentation and site | Technical/user documentation: llms.txt | 4068 | 50 | `06f400314e64c88533f214326b6d2f7f243a7940794d70e8fc7130f0302ff65f` |
| `docs/mac-signing.md` | Documentation and site | Technical/user documentation: mac-signing.md | 2473 | 45 | `dfc5e12700ea459fdf9a4c34df12d8b3d1fdded7ab55f9c6c24391f623531a24` |
| `docs/native-linux-validation.md` | Documentation and site | Technical/user documentation: native-linux-validation.md | 796 | 14 | `b7e7aaa0f79007fcf8314623268808f3dfba6073a395b6ae425c61ec313272fc` |
| `docs/pipeline-stages.md` | Documentation and site | Technical/user documentation: pipeline-stages.md | 5201 | 104 | `0d6076cfc2f6e8fdfd0016b1881fe457d70c1d3fdcc4a4630ad8370fe79ab602` |
| `docs/process-identity-translation.md` | Documentation and site | Technical/user documentation: process-identity-translation.md | 1455 | 31 | `129b0fde1490c275a1e24a1a4622547d07423eccb1943ca246288ab0383ca8cf` |
| `docs/provenance-review.md` | Documentation and site | Technical/user documentation: provenance-review.md | 4367 | 74 | `80df55d54e82c7b679994ec13c2b04409b49b5213050ec1cfc0479688c78626c` |
| `docs/releases/v0.4.0-alpha.2-validation.json` | Documentation and site | Technical/user documentation: v0.4.0-alpha.2-validation.json | 3942 | 111 | `6611fb05a2317855b0485d9e55143b3a595d6b4663c4ee42b07100a202bd2154` |
| `docs/repository-layout.md` | Documentation and site | Technical/user documentation: repository-layout.md | 4443 | 94 | `74c0bdcf3fd4a54329738e80b975a1c4cb2b666f6cf14e2d3b0018f05172a440` |
| `docs/rpc-surface.md` | Documentation and site | Technical/user documentation: rpc-surface.md | 5085 | 95 | `255d80a478e3c591e1660333a4dc6b7b9f6e76a159ce512bf2b29fd19e2ab17f` |
| `docs/runtime-hardening.md` | Documentation and site | Technical/user documentation: runtime-hardening.md | 8377 | 174 | `31c9652ce9209c715bce80053cff9f0621006a31bf4d49710e042387e3813a70` |
| `docs/security-review.md` | Documentation and site | Technical/user documentation: security-review.md | 8255 | 169 | `7ad4cb919a4d10ca338fa6bfa9133063762dfd83bc1c4c2653f334a5166340cb` |
| `docs/site.css` | Documentation and site | Static asset | 4466 | 65 | `fe5e4ceba6751687603e649798974d499fab0b785a208c238d28d0c65a442a83` |
| `docs/sitemap.xml` | Documentation and site | Technical/user documentation: sitemap.xml | 183 | 6 | `e4bd37fcec4d46de5ce68dd20062f6621dca475c9c03bd139e49e921fa43daf0` |
| `docs/social-card.png` | Documentation and site | Static asset | 64264 | binary | `10306d1ef652743cdf2b7194557f4bfe4bff575e2bdf78bb331df801a7a3d8ff` |
| `docs/test-matrix.md` | Documentation and site | Technical/user documentation: test-matrix.md | 4197 | 70 | `53a721d3911915126c5fa351bb480d07d5394e435ea73f3fbafe9cea020754ed` |
| `docs/testing.md` | Documentation and site | Technical/user documentation: testing.md | 4000 | 68 | `ddc7467733e39f2964d03ce3b8abc2e01a5caa0fc94724197823d5b62df77b2c` |
| `docs/wine-setup.md` | Documentation and site | Technical/user documentation: wine-setup.md | 4304 | 111 | `f0e58e217dbd1e3dddc726f57a86b432ff1e17857b4c004bf424672e15752aa3` |
| `docs/wine-stub-crash-guards.md` | Documentation and site | Technical/user documentation: wine-stub-crash-guards.md | 7653 | 166 | `fcd075afa83ea86c62a826090e5a8bf72f4f1991707d272379f2eb1748a18f11` |
| `installers/README.md` | Installers | Shared/Linux installer source, catalog, packaging or documentation: README.md | 7683 | 136 | `df2c736fdf054975b0cf4f3b823f3c95caaa46bafe3979e9ae2affaaf90ff223` |
| `installers/bridge_setup/__init__.py` | Installers | Shared/Linux installer source, catalog, packaging or documentation: __init__.py | 67 | 1 | `343ed96425bca3c88c3e79242487090738221fe849d4c347edbc3821083115e0` |
| `installers/bridge_setup/catalog.json` | Installers | Shared/Linux installer source, catalog, packaging or documentation: catalog.json | 2629 | 53 | `2981a116ab409f64761beaf029e8d03e7eaaa56c2e787a3061ffd0783222eec7` |
| `installers/bridge_setup/core.py` | Installers | Shared/Linux installer source, catalog, packaging or documentation: core.py | 16880 | 326 | `5572e9a3c4d3b3c4ac0ca33efe186f8f3d0997218f70fa794871175e500eccea` |
| `installers/bridge_setup/pe.py` | Installers | Shared/Linux installer source, catalog, packaging or documentation: pe.py | 4134 | 90 | `ea4dceec0f3cbf4a727f75d39d2e38ed104780b800aeff8d5a9250b543657c4d` |
| `installers/bridge_setup/util.py` | Installers | Shared/Linux installer source, catalog, packaging or documentation: util.py | 8362 | 206 | `a30173fefd5f4cc271277ebb6452c57ffe8064d4da2707225f30e38c03e111bb` |
| `installers/build_runtime.py` | Installers | Shared/Linux installer source, catalog, packaging or documentation: build_runtime.py | 8009 | 170 | `cee4f461b7f3df3bcb24a9e9b6d67fefed0fca20985c10ef770af629ee54bd9d` |
| `installers/linux/app.py` | Installers | Shared/Linux installer source, catalog, packaging or documentation: app.py | 12852 | 237 | `64a6e85fea837baa1f16ad87e7adb10b4f5511c59ad706ed4d32916a0df2b87a` |
| `installers/linux/build.py` | Installers | Shared/Linux installer source, catalog, packaging or documentation: build.py | 4969 | 110 | `73bb20819bf4a5241a581c4b0ff2e38a0cb3add3887d3c4b7ee57f1712463885` |
| `installers/linux/install.sh` | Installers | Shared/Linux installer source, catalog, packaging or documentation: install.sh | 1951 | 29 | `3093457672a7ccd7def6f70cc7e62baa8a54b57e6cb2d47c216c52d9da55e42f` |
| `installers/linux/run_root.py` | Installers | Shared/Linux installer source, catalog, packaging or documentation: run_root.py | 5325 | 131 | `fa95ff85f7e219df6f98f68bb3c289aa7775ad70bcdf904bb4257195e724ada4` |
| `installers/linux/uninstall.sh` | Installers | Shared/Linux installer source, catalog, packaging or documentation: uninstall.sh | 642 | 10 | `082de9ad144afe85dd0153e2393542acd2a12fc4b2ee4bc71017d968c6d4bff4` |
| `installers/setup.py` | Installers | Shared/Linux installer source, catalog, packaging or documentation: setup.py | 136 | 5 | `d70960ce31c727cb35c077338dd99f9a1e51ba073fee630bec1f73b694523bc9` |
| `macos/README.md` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: README.md | 5615 | 64 | `dd80c73356fc241945eb9de1e66d223129f86c0bc100be1c5b5836eba2125e0f` |
| `macos/app/BridgeIcon.svg` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: BridgeIcon.svg | 1058 | 11 | `e78dd4fea146ab543b72474987b823f8f9ac4844edd5bbe342a25aac81f087df` |
| `macos/app/ExitLag.swift` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: ExitLag.swift | 11755 | 225 | `a34067714c66fc07cd793cb5de5b32bbecc864eb53a89ae41acaef90e06aa27e` |
| `macos/app/build.sh` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: build.sh | 8994 | 166 | `384d9591f7ae6115d28ec661400b7e56f53bdc2039265bf604efca945906455e` |
| `macos/app/make-icon.swift` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: make-icon.swift | 2815 | 40 | `f7b5eacb32d4448907c9dfa36bc3aab1c3772bac0ec586bd8c32e85fedbe3942` |
| `macos/app/notarize.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: notarize.py | 1314 | 29 | `be5320119177c29bda7a724fcf17492e2333af4004da0fe8bee1281b70a81fe1` |
| `macos/app/sign_payload.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: sign_payload.py | 2240 | 56 | `8e41cb5862c849731bb7f95cede64218ad109e125f189f46a51846ca4628af0b` |
| `macos/auto_agent.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: auto_agent.py | 10144 | 232 | `6c4cdc17464cacc4433574322a87b73d2d9e3a5178dd0ca72ebd95df59ad9e17` |
| `macos/auto_common.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: auto_common.py | 3017 | 83 | `1648f141e68a700f653c30a80f163f99b89a28f09210215583299dec70347492` |
| `macos/auto_service.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: auto_service.py | 8795 | 216 | `6d38a7fb759378dddeb48c59e1960f0dd79b322cfcaecdffc3483defba20aa31` |
| `macos/bridge.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: bridge.py | 22702 | 547 | `1baa9d870ccc3cbaefa27e269f37f0e672a729183f14edcfd6039cdd19f6b535` |
| `macos/build-companion.sh` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: build-companion.sh | 1248 | 49 | `4a4e70090e49f2e794b7f005a76278f612e912e86087353c3717f8af2d9017e9` |
| `macos/build-shim.sh` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: build-shim.sh | 1838 | 34 | `a846cf07330c8c0b4f38e22dd2881822cb50634d5b6a0461e1d5345f427b35eb` |
| `macos/client.sh` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: client.sh | 2934 | 74 | `eff63e1c94f7326bf6dcdc26a8f8c5dd0296f51e4dc811319913fa81b12c7498` |
| `macos/companion.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: companion.py | 6402 | 135 | `e54b5955fd4434a95d4b1576a9e9f5c7353becd3dd32ac767a6b0af795bd2f4d` |
| `macos/control_probe.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: control_probe.py | 7952 | 173 | `24e804c0b15e66a4e96580d4c80b92a9c7edc617e8bdc7385f9e39e9808a47d5` |
| `macos/doctor.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: doctor.py | 1962 | 47 | `456c3b21f9785cd5d43e06ac41ed12a44642089a0745f714692aa167536a4c00` |
| `macos/driver-registration.cpp` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: driver-registration.cpp | 5274 | 120 | `083852bdd0f20b0057e16354393323b5473217f29b36ab3f7bb0cafdd7f309ad` |
| `macos/entry.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: entry.py | 771 | 20 | `86708abf87d42b4e51a2a5ff71179a1addf7108886d13121b413f747acc7883e` |
| `macos/games.auto.map` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: games.auto.map | 412 | 3 | `e474f7973b2caf9913a0795e210cb995bb485493d30779812f32b230cd53cdc1` |
| `macos/games.example.map` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: games.example.map | 412 | 3 | `e474f7973b2caf9913a0795e210cb995bb485493d30779812f32b230cd53cdc1` |
| `macos/pe_check.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: pe_check.py | 4134 | 90 | `ea4dceec0f3cbf4a727f75d39d2e38ed104780b800aeff8d5a9250b543657c4d` |
| `macos/pf_plan.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: pf_plan.py | 1817 | 36 | `bac19d5a17be1f6c8ae5a0e21b2b1e7b1185d805ffc7e2074d0d631967ff18e1` |
| `macos/recover.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: recover.py | 4201 | 100 | `f60ab63519531c5a67a7a6c28214582af3ca2775e3082e385da5e44626cd9f63` |
| `macos/session.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: session.py | 6104 | 133 | `ee0542508eddfc1a870de136163486568e5a63202c5803f39fc224da4a9408a6` |
| `macos/setup_worker.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: setup_worker.py | 450 | 15 | `0202ee74f5e1e09e400307ecade2c4ee1998e553410763c6df1e56c633eb7d76` |
| `macos/supervisor.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: supervisor.py | 6047 | 136 | `fdc1d1bce6f0dd2c8ea28a6da223bc958eeedcf27ecf8c94d8134b6a7f941f69` |
| `macos/test_auto_launcher.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: test_auto_launcher.py | 8427 | 158 | `f9fb3935f82f8115248c5ef3b49e6866f060f31594c7bd3561fdfafffa12728d` |
| `macos/test_bridge.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: test_bridge.py | 9798 | 203 | `5559a6b88a81db13ce539365cdbe97e4da620dc1d1e2457c2ed1322ace1985b8` |
| `macos/test_pf_plan.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: test_pf_plan.py | 1114 | 25 | `d7e12b6f302aa38a6fa515479eb21859736fc080fdb83f546529002a2a006af6` |
| `macos/test_recover.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: test_recover.py | 717 | 17 | `19e1e53756d5ac7951c0f13580d795530001200f20f8c9afe3a7c8af01982d0c` |
| `macos/test_session_control.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: test_session_control.py | 1059 | 31 | `eef133a38d0cbce5d0bfef2b8137ae0b02f98fc0eabcd96642e09031f47b0e62` |
| `macos/test_wine_socket.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: test_wine_socket.py | 4473 | 112 | `6a572b5c3fa71b744c6cc1366dad89b72476d6fa7ff239a65e4a240dc6e65e42` |
| `macos/wine-socket-companion.c` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: wine-socket-companion.c | 8812 | 176 | `f022fdbb5235b4e1dd7b2548904501011da58b598e9a2f0a278db4869173ef3f` |
| `macos/wine_socket.py` | macOS preserved | Platform-specific launcher, routing, packaging, fixture or test: wine_socket.py | 4154 | 80 | `305d8b0aed9c5ff4f22af3edb18f46e0071c0c39f31dc4e603e456eebbd9896b` |
| `shim/nfapi/build.sh` | Windows compatibility | PE DLL/driver source, import declarations or freestanding build: build.sh | 1000 | 50 | `db0702bac79f9ecaede9696f05989a45fc250da2a24513f440e3916e31727840` |
| `shim/nfapi/iphlpapi-missing.def` | Windows compatibility | PE DLL/driver source, import declarations or freestanding build: iphlpapi-missing.def | 57 | 3 | `c593b3d3962ea1571ee7aef4cfa906ebd0972486c737d9b2778b2bdfdddce49f` |
| `shim/nfapi/iphlpapi.def` | Windows compatibility | PE DLL/driver source, import declarations or freestanding build: iphlpapi.def | 77 | 4 | `41ea1d73d9f6157a6388d9fc3ab4e5bcde8bbac718080703bfc9a2d45822c9c9` |
| `shim/nfapi/kernel32.def` | Windows compatibility | PE DLL/driver source, import declarations or freestanding build: kernel32.def | 435 | 23 | `d60858af7041f2d5f9ed9f45e7157790b7424a26b6014a4497ae5381c99fab56` |
| `shim/nfapi/nfapi_stub.cpp` | Windows compatibility | PE DLL/driver source, import declarations or freestanding build: nfapi_stub.cpp | 107020 | 2290 | `9da1a973d4498acdbdbfcabbb5cf443d8c74919071f2afed4b5ba85eb654d22d` |
| `shim/nfapi/powrprof.def` | Windows compatibility | PE DLL/driver source, import declarations or freestanding build: powrprof.def | 56 | 3 | `1effece1a7de00da4c5ced96d255e1d1ddb6610e24776f5091ae8aef9c627d67` |
| `shim/nfapi/ws2_32.def` | Windows compatibility | PE DLL/driver source, import declarations or freestanding build: ws2_32.def | 114 | 9 | `3fbf67bbd6dca0ce1f7264dad63d97ccbbfec73a1d776169ac2ff98884b49622` |
| `shim/nfextlag/build.sh` | Windows compatibility | PE DLL/driver source, import declarations or freestanding build: build.sh | 733 | 23 | `14d984aa35f09e9573aa321681ed9fd88cc46826c719205014288ccb8fbe92d7` |
| `shim/nfextlag/nfextlag.rc` | Windows compatibility | PE DLL/driver source, import declarations or freestanding build: nfextlag.rc | 940 | 33 | `7f7a20d1601192c1734af591f71d5d42644019f2cb60e053b775b3f6b0f97162` |
| `shim/nfextlag/nfextlag_stub.c` | Windows compatibility | PE DLL/driver source, import declarations or freestanding build: nfextlag_stub.c | 1002 | 24 | `68ada2c8293a90f36293f4be73f0dc44fb8df17139ad90f291997f8034e00ccd` |
| `tests/build-nfapi-compat-smoketest.sh` | Validation | Test harness/fixture: build-nfapi-compat-smoketest.sh | 1220 | 29 | `29935c19575353e4bfde5c934c35a19361c3b17e3e1189a045243f4e14dc6e4c` |
| `tests/discovery-test.sh` | Validation | Test harness/fixture: discovery-test.sh | 5780 | 134 | `7c53ae9118f258d233a48287d3b0217aac9d0f3dbe40cae2663078fcf177c853` |
| `tests/doctor-test.sh` | Validation | Test harness/fixture: doctor-test.sh | 3773 | 67 | `5cf280f75852b9e29fa50ba3d30f297ab5283532e2f3d041be171d3c23872513` |
| `tests/external-probe/external-tcp-probe.c` | Validation | Test harness/fixture: external-tcp-probe.c | 4503 | 120 | `26e4ca75e8c874b7c245b07747ff5769056557fb6dfccea36f58aacb0c6c58c9` |
| `tests/external-probe/kernel32.def` | Validation | Test harness/fixture: kernel32.def | 106 | 8 | `2afdfe74bcc91bb791de0b09dc8ad7155d19ffff34c9d9f4a3a0d70bd1a9db8b` |
| `tests/external-probe/ws2_32.def` | Validation | Test harness/fixture: ws2_32.def | 118 | 12 | `0d7711de7b5f96b0eb69d437d6b01150c0a4c5d4872321200b0bee1a2e591abf` |
| `tests/fakegame/sleeper.c` | Validation | Test harness/fixture: sleeper.c | 404 | 10 | `4fda39af7570eefbdddc2018a6834720b05b0b1353435a6dc38d7f92598b3ebe` |
| `tests/harden-runtime-test.sh` | Validation | Test harness/fixture: harden-runtime-test.sh | 13149 | 318 | `e41f2c007e3d4e1803cad62bbf0a1568faa278f48e44b8178b28c8c9abd33632` |
| `tests/identity-assistant-test.sh` | Validation | Test harness/fixture: identity-assistant-test.sh | 5348 | 114 | `364f8a2c20ee43e530a28d1831903344497b380b5a991a3141e9a8de177ebcbb` |
| `tests/installer_fresh_runtime.py` | Validation | Test harness/fixture: installer_fresh_runtime.py | 1142 | 25 | `ad547cea30d178a5411582b60c121acf54fe241b740ac8160c7eee9ae3b39b7f` |
| `tests/ipc-fuzz-test.sh` | Validation | Test harness/fixture: ipc-fuzz-test.sh | 6914 | 134 | `0a0ad2de7ef77fe84302ada894c6e57c302c569c1631f91c8e1a274a4ab45543` |
| `tests/ipc-security-test.sh` | Validation | Test harness/fixture: ipc-security-test.sh | 7549 | 178 | `fcd4a56240646dc13f4cfbe09b05cc91540e2f8dafb0f7c19862bcbc19387877` |
| `tests/ipv6-redirect-test.sh` | Validation | Test harness/fixture: ipv6-redirect-test.sh | 9086 | 200 | `51ce5e579f09ffcdb4ce17d7b562cc1a027c9b7548e2284d02e71fb5055e29bb` |
| `tests/nfapi-compat-smoketest.cpp` | Validation | Test harness/fixture: nfapi-compat-smoketest.cpp | 2169 | 50 | `017eeb1b1481e3526ee64af921b45efa2051f94ac617ffd985da46ce6fcf84e2` |
| `tests/nfapi-reconnect-smoketest.cpp` | Validation | Test harness/fixture: nfapi-reconnect-smoketest.cpp | 683 | 22 | `c4faa5c43950c25d6ee7fad613d97c1ad8f35c3a659cb012a74dda9d725cb5b1` |
| `tests/portable-arch-container.sh` | Validation | Test harness/fixture: portable-arch-container.sh | 2208 | 32 | `a0f471c44c1eed99251cb19af0950c70e85a8d2ec7ea6256238d1f3e84b08c88` |
| `tests/rpc-surface-test.sh` | Validation | Test harness/fixture: rpc-surface-test.sh | 4603 | 113 | `32c006a18ab6582e64921253fec68a9ebf4730623da610d3f1c72f2655c2e908` |
| `tests/run-all.sh` | Validation | Test harness/fixture: run-all.sh | 5557 | 109 | `2445e34e274b0068fb9d59cff6066aa1350bb9304a5c98e22d63c8938bc546f2` |
| `tests/setup-simulation-test.sh` | Validation | Test harness/fixture: setup-simulation-test.sh | 204 | 5 | `d455ad6a5cc07bfaa9f5c76e8ed7b103de20924757c089ba5cf908de42483f77` |
| `tests/test-external-route.sh` | Validation | Test harness/fixture: test-external-route.sh | 2586 | 65 | `53b3bdb9a2485290e97c77c639592fb23fa3fb230ccd99768555d66501765209` |
| `tests/test-identity-map.sh` | Validation | Test harness/fixture: test-identity-map.sh | 3954 | 106 | `9e3b1c4f8bbba6b9c006aa94514e53f51c37b42689706dcde2d62a6115c9a18e` |
| `tests/test-shim-reconnect.sh` | Validation | Test harness/fixture: test-shim-reconnect.sh | 3491 | 92 | `a5ebbb897dbf84be9473807f0853aff24fe4bf6b4771ae0f1a413b0d0d9a949e` |
| `tests/test-tcp-redirect.py` | Validation | Test harness/fixture: test-tcp-redirect.py | 8836 | 226 | `44b54e37aaac508e94b56e6cd60ab7c593242a5d920fabbf6481d07a06bc3c7e` |
| `tests/test-udp-observe.py` | Validation | Test harness/fixture: test-udp-observe.py | 11885 | 268 | `75b005e9af3b13b5de2e597b534928d7624a561e0a29cc9ec883ad7a0b21374a` |
| `tests/test_desktop_ui.py` | Validation | Test harness/fixture: test_desktop_ui.py | 1509 | 31 | `de945e9e5097ae43dfad0b905a76a641d1a1cafd5497e771f1154e098275a557` |
| `tests/test_discovery_filters.py` | Validation | Test harness/fixture: test_discovery_filters.py | 2248 | 49 | `d9c4b948f84dc74ea1d0435cae48353c2b267c228cb8c695333ca5e0394ff0ec` |
| `tests/test_installed_routing.py` | Validation | Test harness/fixture: test_installed_routing.py | 3541 | 68 | `0bfc078a24edff5c28187e2b8bcd0d4e423953cba8337be08223dc437b020ace` |
| `tests/test_installer.py` | Validation | Test harness/fixture: test_installer.py | 10016 | 178 | `57afb819e24cc38e5052c364a9c194329f2368ea5e35193bec1108ef3abfc629` |
| `tests/test_linux_desktop.py` | Validation | Test harness/fixture: test_linux_desktop.py | 2963 | 64 | `9107e8f40fff2ad7f3c80db7b707eec32b47d6a4cb22dff0fc9e04aec3e6d385` |
| `tests/test_mac_distribution.py` | Validation | Test harness/fixture: test_mac_distribution.py | 2686 | 54 | `a6fde8c4e2c5d2c93b5d190d75d817c6a75c3029fe1cec149cfeb1342fa2a596` |
| `tests/test_source_audit.py` | Validation | Test harness/fixture: test_source_audit.py | 3247 | 56 | `940a4df2f294001e58002106d23a1ec205a8d115978b12e5f90a63d8b95b89ef` |
| `tests/validate-external-prefix.sh` | Validation | Test harness/fixture: validate-external-prefix.sh | 4532 | 103 | `7f0e08688d035f7d6ae14b6259738aea8c6f09a9326bc5b986b733f43896fb84` |
| `tests/verify-nfapi-abi.sh` | Validation | Test harness/fixture: verify-nfapi-abi.sh | 1514 | 47 | `cf0af4380e2a38d2613014989e34a0a7a486f91a3f3701ab420065dd77e1ab89` |
| `tools/audit-source.py` | Discovery and operations | Source audit, discovery, setup, ABI or production tooling: audit-source | 3803 | 84 | `334bfd9d58a7797b7fc1889e246377149fd8872284f73050d7f60d4081176625` |
| `tools/check-exitlag-abi.sh` | Discovery and operations | Source audit, discovery, setup, ABI or production tooling: check-exitlag-abi | 6182 | 139 | `a6a02bf4e554a93b50729b26bacd64c8d0d44730e063ebf32434e55fd3c093f7` |
| `tools/check-exitlag-version.sh` | Discovery and operations | Source audit, discovery, setup, ABI or production tooling: check-exitlag-version | 2685 | 64 | `11ca22f20624db64694cf8d42a83c42a141c3869a7123454231727cd8e678e43` |
| `tools/discover-game-processes.py` | Discovery and operations | Source audit, discovery, setup, ABI or production tooling: discover-game-processes | 9745 | 262 | `c34ed4f4c16ff723cba0bcb5c4b2209d81a8e4055c9c810f0eb27ac28071bf0f` |
| `tools/exitlag-doctor.sh` | Discovery and operations | Source audit, discovery, setup, ABI or production tooling: exitlag-doctor | 13653 | 289 | `586aba484b9b667950e79be10a7c5a4f9fdc2e89ab1099aeb2126440906ea485` |
| `tools/exitlag-setup.sh` | Discovery and operations | Source audit, discovery, setup, ABI or production tooling: exitlag-setup | 1195 | 27 | `89765459f982c8666ce512baedfd1274d7a40d328b89390e16f74d5410a8531f` |
| `tools/identity-map-assistant.py` | Discovery and operations | Source audit, discovery, setup, ABI or production tooling: identity-map-assistant | 7283 | 175 | `a529753608d864943b69cb55667c5a34a94fbd5baf5a866e4f4a37ab2ce9c5dc` |
| `tools/install-nfextlag-stub.sh` | Discovery and operations | Source audit, discovery, setup, ABI or production tooling: install-nfextlag-stub | 1817 | 46 | `385e747a6a3b5f0b98185c84a3abbf0c42df1a12f214731664ffa3ec74ee290b` |
| `tools/install-wbemprox-prefix-override.sh` | Discovery and operations | Source audit, discovery, setup, ABI or production tooling: install-wbemprox-prefix-override | 505 | 13 | `2b4f40f7ecfea6de6e215480e2d3559c53ffc2083fec1b9216fb3e98adba9771` |
| `tools/remove-nfextlag-stub.sh` | Discovery and operations | Source audit, discovery, setup, ABI or production tooling: remove-nfextlag-stub | 1143 | 28 | `2a6a6ad863c57cb02a808c5711f21844fa49e1806654ea96cdb4e4c36d76177a` |
| `tools/restore-wbemprox-prefix-override.sh` | Discovery and operations | Source audit, discovery, setup, ABI or production tooling: restore-wbemprox-prefix-override | 507 | 18 | `370038bc56049e25b18a9978b3d13d2d003aaed444eeabe636e787fe0e25dc59` |
| `tools/run-exitlag-gameprefix.sh` | Discovery and operations | Source audit, discovery, setup, ABI or production tooling: run-exitlag-gameprefix | 2244 | 45 | `b1913084048b5e6820ee665c0f28f9163067d4fdc76ecdb071937e97bbfb27ee` |
| `tools/run-exitlag-production.sh` | Discovery and operations | Source audit, discovery, setup, ABI or production tooling: run-exitlag-production | 3362 | 68 | `c250c7b88e8e79f806d800dbf99d3c31fd722d43efd9d08ae4dba5f73983bcc8` |
| `tools/scan-linux-games.py` | Discovery and operations | Source audit, discovery, setup, ABI or production tooling: scan-linux-games | 8308 | 209 | `da490eb85b030bbbdb7735d2f9eb779df3c40a0898e72a62c7e4497317b95e9c` |
| `wine-wbemprox/build-local.sh` | Wine compatibility | Pinned local WMI DLL build | 2853 | 81 | `deb63ad27ae26962f3d4b3ad663f8cabd0c65ae3944bb387436d34fa93678817` |
| `wine-wbemprox/patches/0001-wbemprox-add-logicaldisk-root-directory.patch` | Wine compatibility | LGPL Wine WMI association patch | 5663 | 146 | `7a96cf24b9894c8c1e2da2a0896dd5dda8a9df1ee5f12ff13602c861e8bf2d63` |
