rule ProtectMyTooling
{
    meta:
        description = "Detection patterns for the tool 'ProtectMyTooling' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ProtectMyTooling"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string1 = " --asstrongasfuck-opts " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string2 = " --asstrongasfuck-path " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string3 = " --atompepacker-args " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string4 = " --backdoor-args " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string5 = " --backdoor-path " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string6 = " --backdoor-run " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string7 = " --backdoor-save " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string8 = " --callobf-config " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string9 = " --callobf-path-x64 " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string10 = " --callobf-path-x86 " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string11 = " --confuserex-args " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string12 = " --confuserex-module " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string13 = " --confuserex-modules-in-dir " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string14 = " --confuserex-path " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string15 = " --confuserex-project-file " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string16 = " --confuserex-save-generated-project-file " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string17 = " --donut-cmdline " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string18 = " -e shinject -r -E -t " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string19 = " --enigma-path-x86 " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string20 = " --enigma-protected-exe-cmdline " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string21 = " --hyperion-args " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string22 = " --hyperion-path " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string23 = " --invobf-args " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string24 = " --invobf-powershell " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string25 = " --mangle-strip-go " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string26 = " --netreactor-control-flow-obfuscation " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string27 = " --netreactor-incremental-obfuscation " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string28 = " --netreactor-obfuscate-public-types " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string29 = " --netreactor-stealth-mode " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string30 = " --nimcrypt2-llvm-obfuscator " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string31 = " --nimsyscall-hellsgate " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string32 = " --nimsyscall-noamsi " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string33 = " --nimsyscall-obfuscate " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string34 = " --nimsyscall-obfuscatefunctions " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string35 = " --nimsyscall-peinject " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string36 = " --nimsyscall-reflective " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string37 = " --nimsyscall-remoteinject " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string38 = " --nimsyscall-remotepatchamsi " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string39 = " --nimsyscall-remotepatchetw " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string40 = " --nimsyscall-remoteprocess " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string41 = " --nimsyscall-selfdelete " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string42 = " --nimsyscall-shellcode " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string43 = " --nimsyscall-sleepycrypt " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string44 = " --nimsyscall-syswhispers " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string45 = /\sProtectMyTooling\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string46 = /\sProtectMyToolingGUI\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string47 = /\sRedBackdoorer\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string48 = " --scarecrow-inject " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string49 = " --smartassembly-methodparentobfuscation " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string50 = " --smartassembly-nameobfuscate " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string51 = " --smartassembly-typemethodobfuscation " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string52 = " --srdi-obfuscate-imports " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string53 = /\(\'Successfully\sbackdoored\sentry\spoint\swith\sjump\/call\sto\sshellcode/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string54 = /\.py\scallobf\,upx\,hyperion\s.{0,100}\.exe/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string55 = /\.py\s\-e\sexecute\-assembly\s\-i\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string56 = /\/AsStrongAsFuck\.exe/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string57 = /\/asstrongasfuck\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string58 = /\/confuserex\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string59 = /\/donut\-packer\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string60 = /\/ProtectMyTooling\.git/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string61 = /\/ProtectMyTooling\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string62 = /\/ProtectMyTooling\.yaml/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string63 = /\/ProtectMyToolingGUI\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string64 = /\/RedBackdoorer\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string65 = ":: RedBackdoorer" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string66 = ":: RedWatermarker" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string67 = /\[\+\]\sInjecting\sShellcode\sinto\sRemote\sProcess/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string68 = /\[\+\]\sPPID\sspoofing\senabled/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string69 = /\[\+\]\sUsing\sObfuscator\-LLVM\sto\scompile/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string70 = /\\AsStrongAsFuck\.exe/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string71 = /\\asstrongasfuck\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string72 = /\\beacon\-obf\.exe/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string73 = /\\cobaltProtectMyTooling\.conf/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string74 = /\\Confuser\.CLI\.exe/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string75 = /\\confuserex\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string76 = /\\dbgview64\-infected\.exe/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string77 = /\\donut\-packer\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string78 = /\\Invoke\-Obfuscation/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string79 = /\\ProtectMyTooling\.cna/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string80 = /\\ProtectMyTooling\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string81 = /\\ProtectMyTooling\.yaml/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string82 = /\\ProtectMyToolingGUI\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string83 = /\\RedBackdoorer\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string84 = /\\signed\-executables\\svchost\.exe/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string85 = "163599fee9456a8e2af271824da6e39cfd6aceabb7a62961b8c1a911b94725d6" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string86 = "3615ddbae2c65e978aa8006c26b5c4a66c2e9433a1460b17ef700a39a708e5c1" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string87 = "40ce2ea4f4a90332a6e554ddbd9b801e22df018458127ae6ad1243c7d25a5523" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string88 = "40d86b833531b7f216caa95443f4eb6f0e5b15764072a5708d62380bac2f8ff4" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string89 = "46793c55c24e616a0d4eaaa0090b70bdde05e50c1b58da753d09063e6e838cc6" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string90 = "525bb5e67378b9bdc298aceb9e0108603741ae334e8ce748222999fcb2f1d818" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string91 = "534b0370d1bff7e4a0f327d7fa01679a10cfffc67dbefa5f45e49dbbadec7fa3" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string92 = "5ed84b98241dd1db44e9e3beae6ec07ce8c64cd9200b73954617113578f91317" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string93 = "5fa4acad2bf202e61149a7f47189c4d60ac2823ea26d0f449912ab9d28ad0806" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string94 = "66d16546824f6e98b531bfdfe411ba4b837e99362f735ed2dd61ead2aae4ab91" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string95 = "77c88d4c67b3600e78f82c938d2ef72525277647a27692b2114c9688bf1da121" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string96 = "8a575a3e31ecbc724c5b7755ef14a0f645da3cd33ee57f9c91d74b1d94cdf772" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string97 = "925365b64eb63bafba4fb5c44494428026d98c1a71fc4b54d638c4c22c6e26a7" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string98 = "9521883a37c093f31e9d3fde7d3293f637ea51ce573c3fa7967843b7e51d8dd0" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string99 = "9b33e5ff2cc99df282013554ee5cc3a9a0fe737510af24717b48f93c5d66b94a" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string100 = "9c409702151446f1eb8d951b45a902f2dbad1ebeacab9dd9beeaa5530e65ad0c" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string101 = "a10190903dfb52127ae37214a8c0124c68fc2f7fc91d0bae55eb9f556fa3c8dd" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string102 = "a83c33f484a2cbff3bbefdf51880714968930f69778e8921d8182d2b96e03314" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string103 = "abd9f4b93fc3f2bb0612bfbdef4e0da8797e985e7377ee0c08c2b5b5198c2743" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string104 = "Append IOC watermark to injected shellcode" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string105 = "b3ae1abc15df71a69f3a629fbe5a168acc7514905d8fd82eb8c62e60f61e846e" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string106 = "Backdoored PE file save" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string107 = "be642266-f34d-43c3-b6e4-eebf8e489519" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string108 = "Binary-Offensive/ProtectMyTooling" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string109 = "c39d2a1c303847785a2a2af357dd948f5e6ec8194eb427c52a391db90de34f72" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string110 = "cecbe047e33d2dc3bc06cc7a62546a4e1a793d8da1dde4ba3aa021f944930d6d" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string111 = "d43ceb0d2efb5fdee19d4f7b2448c7f69a6c5d24bfdfd21f5e0fce570fb47d79" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string112 = "d683205c9fad76e28a8e4cd0d72285e9a8573cc95c8b77f30186089459675817" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string113 = "ddcc3057b5c499e1e90d914d9da185d5860f0e9f44a3e5b8f5c9396eaa216ce0" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string114 = "e403c105e8167585b1c431cdc86c943a8f93e876b3940668d088b976d8a1e9a2" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string115 = "e5509a144cb371b7afe6fb6a526fca317688da6b27bfcb7be1faf8fffd58a472" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string116 = "edb161280fe76c89768cab2f9493295671042046f106a7686854f8b5ed118249" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string117 = "ee68d7deb7cefdfca66c078d6036d7aa3aa7afcc62b282999034b4a1faed890d" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string118 = "f109966b6fc1f0ea412a05078baaa79667529be0a387070da7c458a914a07e8e" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string119 = "f487a8b9f72e87a862c6380d316e93dc4bd0a7e7087d6f430e369885db1d5d3d" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string120 = "f80f4c638c843e17f384851f397322eaec414b3718ce79056abc15a6644f466f" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string121 = /hyperion\.exe\s.{0,100}\.exe.{0,100}\s.{0,100}\.exe/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string122 = /mgeeky\.tech\/protectmytooling\// nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string123 = "mgeeky@commandoVM" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string124 = /mimikatz\-obf\.exe/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string125 = /NimPackt\.py\s\-i\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string126 = /Out\-EncodedAsciiCommand\.ps1/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string127 = /Out\-EncodedBinaryCommand\./ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string128 = "Out-EncodedBXORCommand" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string129 = /Out\-EncodedHexCommand\./ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string130 = /Out\-EncodedOctalCommand\./ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string131 = "Out-EncodedSpecialCharOnlyCommand" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string132 = "Out-EncodedWhitespaceCommand" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string133 = "Out-ObfuscatedArrayExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string134 = "Out-ObfuscatedArrayLiteralAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string135 = "Out-ObfuscatedAssignmentStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string136 = /Out\-ObfuscatedAst\.ps1/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string137 = "Out-ObfuscatedAstsReordered " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string138 = "Out-ObfuscatedAttributeAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string139 = "Out-ObfuscatedAttributeBaseAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string140 = "Out-ObfuscatedAttributedExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string141 = "Out-ObfuscatedBaseCtorInvokeMemberExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string142 = "Out-ObfuscatedBinaryExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string143 = "Out-ObfuscatedBlockStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string144 = "Out-ObfuscatedBreakStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string145 = "Out-ObfuscatedCatchClauseAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string146 = "Out-ObfuscatedChildrenAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string147 = "Out-ObfuscatedCommandAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string148 = "Out-ObfuscatedCommandBaseAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string149 = "Out-ObfuscatedCommandElementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string150 = "Out-ObfuscatedCommandExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string151 = "Out-ObfuscatedCommandParameterAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string152 = "Out-ObfuscatedConfigurationDefinitionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string153 = "Out-ObfuscatedConstantExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string154 = "Out-ObfuscatedContinueStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string155 = "Out-ObfuscatedConvertExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string156 = "Out-ObfuscatedDataStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string157 = "Out-ObfuscatedDoUntilStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string158 = "Out-ObfuscatedDoWhileStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string159 = "Out-ObfuscatedDynamicKeywordStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string160 = "Out-ObfuscatedErrorExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string161 = "Out-ObfuscatedErrorStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string162 = "Out-ObfuscatedExitStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string163 = "Out-ObfuscatedExpandableStringExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string164 = "Out-ObfuscatedExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string165 = "Out-ObfuscatedFileRedirectionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string166 = "Out-ObfuscatedForEachStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string167 = "Out-ObfuscatedForStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string168 = "Out-ObfuscatedFunctionDefinitionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string169 = "Out-ObfuscatedFunctionMemberAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string170 = "Out-ObfuscatedHashtableAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string171 = "Out-ObfuscatedIfStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string172 = "Out-ObfuscatedIndexExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string173 = "Out-ObfuscatedInvokeMemberExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string174 = "Out-ObfuscatedLabeledStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string175 = "Out-ObfuscatedLoopStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string176 = "Out-ObfuscatedMemberAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string177 = "Out-ObfuscatedMemberExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string178 = "Out-ObfuscatedMergingRedirectionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string179 = "Out-ObfuscatedNamedAttributeArgumentAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string180 = "Out-ObfuscatedNamedBlockAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string181 = "Out-ObfuscatedParamBlockAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string182 = "Out-ObfuscatedParameterAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string183 = "Out-ObfuscatedParenExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string184 = "Out-ObfuscatedPipelineAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string185 = "Out-ObfuscatedPipelineBaseAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string186 = "Out-ObfuscatedPropertyMemberAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string187 = "Out-ObfuscatedRedirectionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string188 = "Out-ObfuscatedReturnStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string189 = "Out-ObfuscatedScriptBlockAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string190 = "Out-ObfuscatedScriptBlockExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string191 = "Out-ObfuscatedStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string192 = "Out-ObfuscatedStatementBlockAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string193 = "Out-ObfuscatedStringCommand" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string194 = "Out-ObfuscatedStringConstantExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string195 = "Out-ObfuscatedSubExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string196 = "Out-ObfuscatedSwitchStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string197 = "Out-ObfuscatedThrowStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string198 = "Out-ObfuscatedTokenCommand" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string199 = "Out-ObfuscatedTrapStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string200 = "Out-ObfuscatedTryStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string201 = "Out-ObfuscatedTypeConstraintAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string202 = "Out-ObfuscatedTypeDefinitionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string203 = "Out-ObfuscatedTypeExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string204 = "Out-ObfuscatedUnaryExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string205 = "Out-ObfuscatedUsingExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string206 = "Out-ObfuscatedUsingStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string207 = "Out-ObfuscatedVariableExpressionAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string208 = "Out-ObfuscatedWhileStatementAst " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string209 = "Out-ParenthesizedString " nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string210 = /packers\/invobf\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string211 = /packers\\invobf\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string212 = "pip install donut-shellcode" nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string213 = /ProtectMyToolingGUI\.pyw/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string214 = /ProtectMyTooling\-master\.zip/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string215 = /putty\-infected\.exe/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string216 = /Rubeus\-obf\.exe/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string217 = /upx\s\-\-brute\s.{0,100}\.exe/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string218 = /upx\s\-ultra\-brute\s.{0,100}\.exe/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string219 = "Your finest PE backdooring companion" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
