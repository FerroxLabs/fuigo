# R084 appendix — P79 Windows round: every run

Companion of `R084-p79.md` §9. Nothing here is a claim; it is the list of runs.

## A. SeanDesktop (native Windows 11, NTFS, rustc 1.94.0 msvc), `C:\p79\w\<tag>.out` / `.log`

One cargo command per row, through `C:\p79\w\wrun.ps1` (stdout+stderr to `<tag>.out`; start, command, exit code,
the state of the real `%USERPROFILE%\.fuigo` before and after, and the sha256 of the `.out` to `<tag>.log`).
`temp` is where `TEMP`/`TMP` pointed: `C:` = `C:\p79\tmp` (8.3 short names enabled), `F:` = `F:\Temp\Codex`
(none). `home` = `same` when the entry count, the lock-file count and the newest modification time under the real
`.fuigo` were identical before and after the run. Times are local (+07:00), 2026-10-03. Exit 101 rows named
`wmut-*` are mutants (expected); the two `*-shell` rows are the failed `fuigo-shell` builds (§9.0.1 of the receipt).
`w7-lib` is the one failing run of a working copy (a test of mine that assumed the account is bound by a deny ACL).
Rows before `f4-*` ran on working copies or earlier commits of the round.

| ended | tag | cargo … | temp | exit | home | sha256 of `.out` |
|---|---|---|---|---|---|---|
| 03:54:36 | `w1-lib` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `c04e178ecd91c83f9d4439c28d874c586f0f14e0911458c41495976ab2dd60c1` |
| 03:57:33 | `parent-probe` | `test -p fuigo-config --lib -- --exact fs_atomic::p72_tests::p79w_parent_probe_respelling --nocapture` | C: parent | 0 | same | `9c859517ae487f58e6f77eec7aab9b631d81e8bfba70051d7a07c2571de14956` |
| 03:58:15 | `w2-lib` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `c768183d2aa59e42dadd7bf44b5aa59fd1f70dea85703e1dda5a06936d66b798` |
| 03:58:40 | `w2-clippy` | `clippy --all-targets -p fuigo-config` | F: | 0 | same | `6dc1809c8d994d12433cae76da515d37e5c3198a109a9977a8057f62b675fc2b` |
| 03:59:40 | `w3-shell` | `test -p fuigo-shell --features test-support,config-docs --lib -- session::prompt_history --nocapture` | C: | 101 | same | `c706f687c9d0c38ead314d60e03a2d69fbbf862874ac6a484826e515358e0efa` |
| 04:00:05 | `w4-shell` | `test -p fuigo-shell --features test-support,config-docs --lib -- session::prompt_history --nocapture` | C: | 101 | same | `b3305763648a111737df846807ca6806dea76717b26d584d8db83d56e16ad2d9` |
| 04:02:09 | `wmut-c1-W1` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `0e2cfcb515481aba3747e8a1c7b67bfa91455d56f769364def6772dc9fb1af96` |
| 04:02:25 | `wmut-c1-W2` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `fd8b21becfc5bb7783696600a1eafda3841271f104844c8c982c6af2141b1288` |
| 04:02:36 | `wmut-c1-W3` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 0 | same | `1a181b6e20eab4fcc8c496da758e9ba3ba2628e7e97e93ad614c7fa807e56e9a` |
| 04:02:51 | `wmut-c1-W4` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `cec29f7323ee2106b94ccfff5efa0db2869b2ff91f7ad5938c2b0cb030faf5ff` |
| 04:03:48 | `w5-p79` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 0 | same | `38f5d74e3d7dc084dc7d1ed2d2a4c6c540017844184fcf294100ae92e7cd78c4` |
| 04:03:59 | `wmut-c2pre-W3` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `e837e7d35db1926c026d6cecad08cd98102220c59a019c64cb3b12d2da9f3c6a` |
| 04:04:57 | `w6-lib` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `424beb4c8a83919ca13a8763c7472e8b318fcb2902957749c73ba9230c138f03` |
| 04:12:51 | `w7-lib` | `test -p fuigo-config --lib -- --nocapture` | C: | 101 | same | `21b1e4595a49160583688f4f22fbffeeabb5f25c9a524aeeff858d266105e1c8` |
| 04:14:18 | `w8-lib` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `ccaec49cdb8b8222d7a740f2a7ee4c9261f7b7db23f47c0bed8a8c9dfeabc600` |
| 04:14:21 | `w8-clippy` | `clippy --all-targets -p fuigo-config` | F: | 0 | same | `2bc621eaf3f594b90d9116af3caa02f0687e33debb29f4ed4eb2bc2dba1587bb` |
| 04:15:43 | `wmut-c2-W1` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `5c39c3f1610b74c7f4b89b694555613563d7e153207a08d995e3f90fa5df0cd4` |
| 04:16:00 | `wmut-c2-W3` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `e699a2981472957e6218bb6be4ff68ec3eb365cd47230a9964294cecc3417b40` |
| 04:16:17 | `wmut-c2-W4` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `c145af9503751853e78c3010e02ea321d1468d0620f8875c9d76efd1871b222e` |
| 04:16:43 | `wmut-c2b-W2` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `ae560c6e77a1f04d8d43ed828233045055588b98d6ef827318efb473f075dc95` |
| 04:19:34 | `w9-lib` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `065527adfceda90beb751935c01e974ffae35f0953b97ac7ed600306b1b72242` |
| 04:21:58 | `w10-lib` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `2f62285af945c70fcd017d4df1711b05868a654a238eae8d84f16c1221666539` |
| 04:23:10 | `wmut-c3-W1` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `164a0639350b2157f9bb0c86e895366311ffbbc9d0008be5ecaf8e520da742a0` |
| 04:23:28 | `wmut-c3-W2` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `e17eab18cb70f12a0107e3e3a1ddb6616c2b2132fe1437db5e115428a537a4e4` |
| 04:23:44 | `wmut-c3-W3` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `a7cd2b6c38ec99153bddd8891fa3b8179e998e1618dd92f4d4b79611f8f029b5` |
| 04:24:00 | `wmut-c3-W4` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `b3e1f71afbe93a911e3b030c06fbd4235229a5eb4e236c471359e5688da59215` |
| 04:32:03 | `w11-lib` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `c2bdcbcd6af53a76b55fc1845fda72b468366c88ef78ad1bd2aadc99ae949d81` |
| 04:33:41 | `f1-lib-1` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `861c50bf0e97f32f2bf795c0092d2ebd740f28d0241152bba605e29daaadbe74` |
| 04:33:56 | `f1-lib-2` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `72b6280d4a2349aaa1518f5b042b2f95f4aba1a9cf8098d120eb04b3c3349f1e` |
| 04:34:10 | `f1-lib-3` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `5ea5ef94ae11a567e2dd68146d578a0bc0579da930b7639acf92096103a3e98b` |
| 04:34:27 | `f1-lib-F` | `test -p fuigo-config --lib -- --nocapture` | F: | 0 | same | `a5cf55dcc6427108d338885a66775bf1600f29b86cb79566dfda127e79ee76bd` |
| 04:34:50 | `wmut-f1-W1` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `65d4d97aa9eaa195f724a056f0d74cd389a6dac84fb4e7ed3fdd4a6b3af791de` |
| 04:35:07 | `wmut-f1-W2` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `a5e9dc149dcc8649344d1196d78681f6344d4326b51dece4c09ec876cd38b0f3` |
| 04:35:23 | `wmut-f1-W3` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `dc0a69743fd3e84561f083939f9e5767fd58beef3923ad97d65d27c87cacda89` |
| 04:35:35 | `wmut-f1-W4` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `8b8024ada3920521b4101fe5d6b11fb6730d87168c69c88d5ff3380905d54997` |
| 04:35:38 | `f1-clippy` | `clippy --all-targets -p fuigo-config` | F: | 0 | same | `40a1cfbb42129d4be513fe23df12d1cce87a34dc3297ff288ddf1afea31c4813` |
| 04:46:03 | `w12-p79-1` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 0 | same | `4a684e2aa45e3bf99852760ac714566bae673962703cd12fb40201ccbdd6f019` |
| 04:46:12 | `w12-p79-2` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 0 | same | `69c520fbd1c03e3af06742c7c17b6103b06369fc7de40a41029298bc897c7931` |
| 04:46:22 | `w12-p79-3` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 0 | same | `9cbb8d82701e46ccc7234daa68d1d84099e6479f78f0433c9ed065e06bc8933d` |
| 04:46:32 | `w12-p79-4` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 0 | same | `d0c3d1b283207f6921c0a943141102ec906549fb080d4408d378c485d5e82e2c` |
| 04:46:41 | `w12-p79-5` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 0 | same | `a69291ac25f500421d81e51489583487984778ab33a3cdfbbb545207575475e9` |
| 04:46:51 | `w12-p79-6` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 0 | same | `9e61d843910c2a85a6274d7c55299ae1d7f7aa72dba8012bee064182b3e8007c` |
| 04:47:11 | `wmut-inv1-W2` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `5fbaceddb1a7b8e4e7e63e9e048566306d09ec7d27abd4dbffeb7479341ca669` |
| 04:47:22 | `wmut-inv2-W2` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `d72f9d0be5c5ea703cbf45a7a44e2512c89a78441023d64a1212e5229e08aae3` |
| 04:47:34 | `wmut-inv3-W2` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `ff2c42546f6fca7945b24da7415259f63fb4593be638698b91e8fe4b20a19e61` |
| 04:47:46 | `wmut-inv4-W2` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `442de0f4672852593d019187789d67252efb52035cf566473d91ede8f2c69b6a` |
| 04:47:57 | `wmut-inv5-W2` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `ae3c7ea885b3b4075e2bef0a54ae0fe6bfa29ef9d569c00d3b04dc9434d184e1` |
| 04:48:09 | `wmut-inv6-W2` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `14c495a1e2261ac60d9438257a171eb641cc452ac997d717f955a7be292defea` |
| 04:50:30 | `w13-lib` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `03adbbf82ecc0aa2ed9e06a7ac95a40fd09651ac9ca36f38d4cf9b76db08cd92` |
| 04:50:32 | `w13-clippy` | `clippy --all-targets -p fuigo-config` | F: | 0 | same | `76f563cf81d371fdb16ff8f52512304112a2d836a6254532483a0841100d4756` |
| 04:51:42 | `f2-lib-1` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `8c2322931ddf55727f394d8fcb81de74b74f3c33980713f3f8bf56c8cd3013b7` |
| 04:51:54 | `f2-lib-2` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `71e5d51e530ae8d672848dd7bb1eabf26ea4f66fb9fac6d95df668be560b1e63` |
| 04:52:07 | `f2-lib-3` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `9e54258bc8d09847e0b7dd9f9423cff88b61c72fad95d95080a664ead9330327` |
| 04:52:19 | `f2-lib-4` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `3c6a343ac668b0d69f07fb42ef1d21e73428fdb48dacece238b6c8ffe3705aab` |
| 04:52:32 | `f2-lib-5` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `faefe420baa000264cc37215680561fdbb966bf548f31e857da14478f3f45c21` |
| 04:52:44 | `f2-lib-6` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `9d3a3f1c2d58c9e9515428a1ba3695a84d3b8c3958056bb1de02d07d42291f37` |
| 04:52:57 | `f2-lib-7` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `59844b901a2189914cd2fa8a02f44837514b5309f0219248e6071abe869bd48f` |
| 04:53:09 | `f2-lib-8` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `f3a4d108f7f0d2968bf76d02482443e53255c2457bfc05f2ac156a2e0ff5537b` |
| 04:53:22 | `f2-lib-9` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `c7754042b5621facba47e8a8f0bdf4fd50c9d1583081f592be1bf70d910b8adf` |
| 04:53:34 | `f2-lib-10` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `06a63acbc1dab0d9bbf8d337fb9d514e041524438b88bb277a7631b8460868a2` |
| 04:53:59 | `wmut-f2-W1` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `319b46899b840e589d438e9f77341e602f7a7f9d0c500b9fa1dae7d2c2905fbc` |
| 04:54:10 | `wmut-f2-W2` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `e0c24e7ee815d8d005376853bca2f0a87daaf28314444bcca7de90a3253fb094` |
| 04:54:21 | `wmut-f2-W3` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `cae0145972d8c91e4fe46fe82b2e1753c04f8e3180106f8ab0c633b7e07697f8` |
| 04:54:32 | `wmut-f2-W4` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `149cd148042e0e77708395531f3fb726e0cba86f7b2600f5bde58249b5ae92cd` |
| 04:54:46 | `f2-lib-F` | `test -p fuigo-config --lib -- --nocapture` | F: | 0 | same | `e27459cfb14daf862f9e21b80a6da6c62dc311dbb63dfb09f07e99cbc4bd58bb` |
| 04:54:50 | `f2-clippy` | `clippy --all-targets -p fuigo-config` | F: | 0 | same | `3e2c51c66f5fcd0efb801103a241c11361c5f02e739734828e288ceaddfe912f` |
| 05:04:18 | `w14-lib` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `51ede0115c073ce94783f2c8d581cde05e1043edf16e5942b3efd80b7c123c23` |
| 05:05:28 | `f3-lib-1` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `69bad3e6a1d4cc2c496dd34910d024fd83d041c083b12192b12508e16c5da47b` |
| 05:05:41 | `f3-lib-2` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `58348568ebad9e09adc5bb0285adcbdc732630985963d7a4c9d35211013c3de3` |
| 05:05:53 | `f3-lib-3` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `114531f8210904baecb59a2030bb2cb52d7d8f7ad2b3e9594297626ed1d322e7` |
| 05:06:06 | `f3-lib-F` | `test -p fuigo-config --lib -- --nocapture` | F: | 0 | same | `22272bd19f0e890b4ee89b7a926822a17b075eb7a51a8290b2942ec5958b2196` |
| 05:06:18 | `wmut-f3-W1` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `e10a18f12fcbc3fbe746385842cea3316ebc7ea211d8b1d41cd941dea78616b0` |
| 05:06:29 | `wmut-f3-W2` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `4cc3578b03a527bb57d0df8d2a0353d6bf8309545fc8d2276e7042f3c728e2ed` |
| 05:06:40 | `wmut-f3-W3` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `f11bae4bea4cd8645692a671466cba932fd582e80c93c468532785d1bb9d3825` |
| 05:06:51 | `wmut-f3-W4` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `12c2dd0a4c3705d6c5ede0582c5269e05cd28cc98a3532fb8a69ff3ee4b2891d` |
| 05:06:55 | `f3-clippy` | `clippy --all-targets -p fuigo-config` | F: | 0 | same | `33ebf1fd2c079245e4279559dc0344129782ee24843d277bcb2c2a07010bd312` |
| 05:18:43 | `w15-lib` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `cb7c9fc836d652ef8ebf0cc1ddcc91331148f7d88505def67b2838c717d99a0b` |
| 05:19:04 | `wmut-pre7-W3` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `8a3d33d9b345c4e261a3060d0f6b76513c9a1c47236444c3a379eeaf95098edf` |
| 05:19:16 | `wmut-pre7-W6` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `59a9dd30fb6b3bcc887a7c4763e6cf4bef248847290c6f0e1ce4919247c3f398` |
| 05:20:52 | `f4-lib-1` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `233b651fed3c5cbcb45752a0805369d316a1fd62242353f13eb0b18f23d710b9` |
| 05:21:04 | `f4-lib-2` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `377922b466d5347b157312df098f795b28ee19444f601736cc2c37b0f9a42fc2` |
| 05:21:17 | `f4-lib-3` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `b69f1b509f44be0f8412a93f564fc41c586e16e2fa8d21b1b010d3e9db63193c` |
| 05:21:29 | `f4-lib-4` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `2940988670265ac435a1ee79add282da1ccddd8b278ef3f298d26ca6c4ba3548` |
| 05:21:42 | `f4-lib-5` | `test -p fuigo-config --lib -- --nocapture` | C: | 0 | same | `b1bc7c086a90d0af3112f027c82f63e575125ca4d23579aa8ea6d50c180a374d` |
| 05:21:54 | `f4-lib-F` | `test -p fuigo-config --lib -- --nocapture` | F: | 0 | same | `08f93a27d2d58ece9eb4c27467d00cd401c0868fd5093739c361c8dcbf82d9e3` |
| 05:22:06 | `wmut-f4-W1` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `b790b1ec3f6f60b2de046a69128df0e755d3fbf99f043f2b48792f754359037c` |
| 05:22:18 | `wmut-f4-W2` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `3ef721edc77708211d6f8806cbbe15dc99ec8bdef60e0406bb6eb46dc858fa33` |
| 05:22:40 | `wmut-f4-W3` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `1305e5704d1f8a79a87189821fc2d1324262380ebd21f2ab7e16c0eb17216d98` |
| 05:22:51 | `wmut-f4-W4` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `b4ffe31043bf572980510627a71f737991658b14329e446374672b1aee03840b` |
| 05:23:02 | `wmut-f4-W6` | `test -p fuigo-config --lib -- fs_atomic::p79_tests` | C: | 101 | same | `cf275e6275f4bbff222168f033bb3e1261d5ca4c1ed933f675b614a46231eb36` |
| 05:23:06 | `f4-clippy` | `clippy --all-targets -p fuigo-config` | F: | 0 | same | `1990bc7a0a3994890259e1949cd3e064437691d9c342ce27cffbc487b7a3a545` |

## B. Hetzner, lane `p79w` (`/root/fuigo-builds/p79w/logs/`; `SHA256SUMS` there lists every log)

`run.sh <tag> <cargo args>` = `slot-run.sh p79w nice -n 10 timeout 3000 cargo <args>` with the protocol's
environment and `CARGO_TARGET_DIR=/root/fuigo-builds/p79w/target`. `tree` is the lane checkout's HEAD and how many
files differed from it (0 = a clean checkout of a commit). `*-vfat` runs had `FUIGO_P79_CI_DIR` on a vfat loop mount.
Mutant runs are in `mut-<label>/` (one log per mutant, `summary.txt`), not in this table.

| log | tree | first `test result` line | cargo exit |
|---|---|---|---|
| `d10-clippy-config.log` | c9284612 dirty=2 | (no test result line: clippy) | EXIT=0 |
| `d10-config-ext4.log` | c9284612 dirty=2 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d10-config-vfat.log` | c9284612 dirty=2 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d11-clippy-config.log` | f66ea751 dirty=2 | (no test result line: clippy) | EXIT=0 |
| `d11-config-ext4.log` | f66ea751 dirty=2 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d11-config-vfat.log` | f66ea751 dirty=2 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d12-clippy-config.log` | f66ea751 dirty=2 | (no test result line: clippy) | EXIT=0 |
| `d12-config-ext4.log` | f66ea751 dirty=2 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d12-config-vfat.log` | f66ea751 dirty=2 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d13-clippy-config.log` | dadd64b2 dirty=2 | (no test result line: clippy) | EXIT=0 |
| `d13-config-ext4.log` | dadd64b2 dirty=2 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d13-config-vfat.log` | dadd64b2 dirty=2 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d14-clippy-config.log` | 0f3b88ef dirty=2 | (no test result line: clippy) | EXIT=0 |
| `d14-config-ext4.log` | 0f3b88ef dirty=2 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d14-config-vfat.log` | 0f3b88ef dirty=2 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d1-config-ext4.log` | bf4eb5d5 dirty=8 | ok. 85 passed; 0 failed; 2 ignored | EXIT=0 |
| `d2-config-ext4.log` | bf4eb5d5 dirty=4 | ok. 86 passed; 0 failed; 2 ignored | EXIT=0 |
| `d2-config-vfat.log` | bf4eb5d5 dirty=4 | ok. 86 passed; 0 failed; 2 ignored | EXIT=0 |
| `d3-clippy-config.log` | bf4eb5d5 dirty=4 | (no test result line: clippy) | EXIT=0 |
| `d3-clippy.log` | bf4eb5d5 dirty=4 | (no test result line: clippy) | EXIT=0 |
| `d3-config-full.log` | bf4eb5d5 dirty=4 | ok. 310 passed; 0 failed; 2 ignored | EXIT=0 |
| `d3-render.log` | bf4eb5d5 dirty=4 | ok. 28 passed; 0 failed; 0 ignored | EXIT=0 |
| `d3-shell.log` | bf4eb5d5 dirty=4 | ok. 66 passed; 0 failed; 0 ignored | EXIT=0 |
| `d4-config-ext4.log` | bf4eb5d5 dirty=4 | ok. 86 passed; 0 failed; 2 ignored | EXIT=0 |
| `d4-config-vfat.log` | bf4eb5d5 dirty=4 | ok. 86 passed; 0 failed; 2 ignored | EXIT=0 |
| `d5-config-ext4.log` | bf4eb5d5 dirty=4 | ok. 87 passed; 0 failed; 2 ignored | EXIT=0 |
| `d5-config-vfat.log` | bf4eb5d5 dirty=4 | ok. 87 passed; 0 failed; 2 ignored | EXIT=0 |
| `d6-clippy-config.log` | bf4eb5d5 dirty=4 | (no test result line: clippy) | EXIT=0 |
| `d6-config-ext4.log` | bf4eb5d5 dirty=4 | ok. 88 passed; 0 failed; 2 ignored | EXIT=0 |
| `d6-config-vfat.log` | bf4eb5d5 dirty=4 | ok. 88 passed; 0 failed; 2 ignored | EXIT=0 |
| `d7-clippy-config.log` | 203cdec1 dirty=2 | (no test result line: clippy) | EXIT=0 |
| `d7-config-ext4.log` | 203cdec1 dirty=2 | ok. 89 passed; 0 failed; 2 ignored | EXIT=0 |
| `d7-config-vfat.log` | 203cdec1 dirty=2 | ok. 89 passed; 0 failed; 2 ignored | EXIT=0 |
| `d8-clippy-config.log` | 203cdec1 dirty=2 | (no test result line: clippy) | EXIT=0 |
| `d8-config-ext4.log` | 203cdec1 dirty=2 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d8-config-vfat.log` | 203cdec1 dirty=2 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d9-rep10.log` | c9284612 dirty=1 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d9-rep11.log` | c9284612 dirty=1 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d9-rep12.log` | c9284612 dirty=1 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d9-rep1.log` | c9284612 dirty=1 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d9-rep2.log` | c9284612 dirty=1 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d9-rep3.log` | c9284612 dirty=1 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d9-rep4.log` | c9284612 dirty=1 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d9-rep5.log` | c9284612 dirty=1 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d9-rep6.log` | c9284612 dirty=1 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d9-rep7.log` | c9284612 dirty=1 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d9-rep8.log` | c9284612 dirty=1 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `d9-rep9.log` | c9284612 dirty=1 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `c2-config-ext4.log` | 203cdec1 dirty=0 | ok. 88 passed; 0 failed; 2 ignored | EXIT=0 |
| `c2-config-vfat.log` | 203cdec1 dirty=0 | ok. 88 passed; 0 failed; 2 ignored | EXIT=0 |
| `c3-config-ext4.log` | c9284612 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `c3-config-vfat.log` | c9284612 dirty=0 | FAILED. 89 passed; 1 failed; 2 ignored | EXIT=101 |
| `f1-clippy.log` | f66ea751 dirty=0 | (no test result line: clippy) | EXIT=0 |
| `f1-config-ext4.log` | f66ea751 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f1-config-full.log` | f66ea751 dirty=0 | ok. 314 passed; 0 failed; 2 ignored | EXIT=0 |
| `f1-config-vfat.log` | f66ea751 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f1-hooks.log` | f66ea751 dirty=0 | ok. 273 passed; 0 failed; 1 ignored | EXIT=0 |
| `f1-render.log` | f66ea751 dirty=0 | ok. 28 passed; 0 failed; 0 ignored | EXIT=0 |
| `f1-rep1.log` | f66ea751 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f1-rep2.log` | f66ea751 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f1-rep3.log` | f66ea751 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f1-rep4.log` | f66ea751 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f1-rep5.log` | f66ea751 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f1-rep6.log` | f66ea751 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f1-rep7.log` | f66ea751 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f1-rep8.log` | f66ea751 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f1-shell.log` | f66ea751 dirty=0 | ok. 66 passed; 0 failed; 0 ignored | EXIT=0 |
| `f2-clippy.log` | dadd64b2 dirty=0 | (no test result line: clippy) | EXIT=0 |
| `f2-config-ext4.log` | dadd64b2 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f2-config-full.log` | dadd64b2 dirty=0 | ok. 314 passed; 0 failed; 2 ignored | EXIT=0 |
| `f2-config-vfat.log` | dadd64b2 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f2-hooks.log` | dadd64b2 dirty=0 | ok. 273 passed; 0 failed; 1 ignored | EXIT=0 |
| `f2-render.log` | dadd64b2 dirty=0 | ok. 28 passed; 0 failed; 0 ignored | EXIT=0 |
| `f2-rep1.log` | dadd64b2 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f2-rep2.log` | dadd64b2 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f2-rep3.log` | dadd64b2 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f2-rep4.log` | dadd64b2 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f2-rep5.log` | dadd64b2 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f2-rep6.log` | dadd64b2 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f2-rep7.log` | dadd64b2 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f2-rep8.log` | dadd64b2 dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f2-shell.log` | dadd64b2 dirty=0 | ok. 66 passed; 0 failed; 0 ignored | EXIT=0 |
| `f3-clippy.log` | 0f3b88ef dirty=0 | (no test result line: clippy) | EXIT=0 |
| `f3-config-ext4.log` | 0f3b88ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f3-config-full.log` | 0f3b88ef dirty=0 | ok. 314 passed; 0 failed; 2 ignored | EXIT=0 |
| `f3-config-vfat.log` | 0f3b88ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f3-hooks.log` | 0f3b88ef dirty=0 | ok. 273 passed; 0 failed; 1 ignored | EXIT=0 |
| `f3-render.log` | 0f3b88ef dirty=0 | ok. 28 passed; 0 failed; 0 ignored | EXIT=0 |
| `f3-rep1.log` | 0f3b88ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f3-rep2.log` | 0f3b88ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f3-rep3.log` | 0f3b88ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f3-rep4.log` | 0f3b88ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f3-rep5.log` | 0f3b88ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f3-rep6.log` | 0f3b88ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f3-rep7.log` | 0f3b88ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f3-rep8.log` | 0f3b88ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f3-shell.log` | 0f3b88ef dirty=0 | ok. 66 passed; 0 failed; 0 ignored | EXIT=0 |
| `f4-clippy.log` | eed8b3ef dirty=0 | (no test result line: clippy) | EXIT=0 |
| `f4-config-ext4.log` | eed8b3ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f4-config-full.log` | eed8b3ef dirty=0 | ok. 314 passed; 0 failed; 2 ignored | EXIT=0 |
| `f4-config-vfat.log` | eed8b3ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f4-hooks.log` | eed8b3ef dirty=0 | ok. 273 passed; 0 failed; 1 ignored | EXIT=0 |
| `f4-render.log` | eed8b3ef dirty=0 | ok. 28 passed; 0 failed; 0 ignored | EXIT=0 |
| `f4-rep1.log` | eed8b3ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f4-rep2.log` | eed8b3ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f4-rep3.log` | eed8b3ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f4-rep4.log` | eed8b3ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f4-rep5.log` | eed8b3ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f4-rep6.log` | eed8b3ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f4-rep7.log` | eed8b3ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f4-rep8.log` | eed8b3ef dirty=0 | ok. 90 passed; 0 failed; 2 ignored | EXIT=0 |
| `f4-shell.log` | eed8b3ef dirty=0 | ok. 66 passed; 0 failed; 0 ignored | EXIT=0 |
