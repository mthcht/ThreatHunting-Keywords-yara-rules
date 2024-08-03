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
        $string1 = /\s\-\-asstrongasfuck\-opts\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string2 = /\s\-\-asstrongasfuck\-path\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string3 = /\s\-\-atompepacker\-args\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string4 = /\s\-\-backdoor\-args\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string5 = /\s\-\-backdoor\-path\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string6 = /\s\-\-backdoor\-run\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string7 = /\s\-\-backdoor\-save\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string8 = /\s\-\-callobf\-config\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string9 = /\s\-\-callobf\-path\-x64\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string10 = /\s\-\-callobf\-path\-x86\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string11 = /\s\-\-confuserex\-args\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string12 = /\s\-\-confuserex\-module\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string13 = /\s\-\-confuserex\-modules\-in\-dir\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string14 = /\s\-\-confuserex\-path\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string15 = /\s\-\-confuserex\-project\-file\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string16 = /\s\-\-confuserex\-save\-generated\-project\-file\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string17 = /\s\-\-donut\-cmdline\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string18 = /\s\-e\sshinject\s\-r\s\-E\s\-t\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string19 = /\s\-\-enigma\-path\-x86\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string20 = /\s\-\-enigma\-protected\-exe\-cmdline\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string21 = /\s\-\-hyperion\-args\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string22 = /\s\-\-hyperion\-path\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string23 = /\s\-\-invobf\-args\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string24 = /\s\-\-invobf\-powershell\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string25 = /\s\-\-mangle\-strip\-go\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string26 = /\s\-\-netreactor\-control\-flow\-obfuscation\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string27 = /\s\-\-netreactor\-incremental\-obfuscation\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string28 = /\s\-\-netreactor\-obfuscate\-public\-types\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string29 = /\s\-\-netreactor\-stealth\-mode\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string30 = /\s\-\-nimcrypt2\-llvm\-obfuscator\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string31 = /\s\-\-nimsyscall\-hellsgate\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string32 = /\s\-\-nimsyscall\-noamsi\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string33 = /\s\-\-nimsyscall\-obfuscate\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string34 = /\s\-\-nimsyscall\-obfuscatefunctions\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string35 = /\s\-\-nimsyscall\-peinject\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string36 = /\s\-\-nimsyscall\-reflective\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string37 = /\s\-\-nimsyscall\-remoteinject\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string38 = /\s\-\-nimsyscall\-remotepatchamsi\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string39 = /\s\-\-nimsyscall\-remotepatchetw\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string40 = /\s\-\-nimsyscall\-remoteprocess\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string41 = /\s\-\-nimsyscall\-selfdelete\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string42 = /\s\-\-nimsyscall\-shellcode\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string43 = /\s\-\-nimsyscall\-sleepycrypt\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string44 = /\s\-\-nimsyscall\-syswhispers\s/ nocase ascii wide
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
        $string48 = /\s\-\-scarecrow\-inject\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string49 = /\s\-\-smartassembly\-methodparentobfuscation\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string50 = /\s\-\-smartassembly\-nameobfuscate\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string51 = /\s\-\-smartassembly\-typemethodobfuscation\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string52 = /\s\-\-srdi\-obfuscate\-imports\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string53 = /\(\'Successfully\sbackdoored\sentry\spoint\swith\sjump\/call\sto\sshellcode/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string54 = /\.py\scallobf\,upx\,hyperion\s.{0,1000}\.exe/ nocase ascii wide
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
        $string65 = /\:\:\sRedBackdoorer/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string66 = /\:\:\sRedWatermarker/ nocase ascii wide
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
        $string85 = /163599fee9456a8e2af271824da6e39cfd6aceabb7a62961b8c1a911b94725d6/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string86 = /3615ddbae2c65e978aa8006c26b5c4a66c2e9433a1460b17ef700a39a708e5c1/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string87 = /40ce2ea4f4a90332a6e554ddbd9b801e22df018458127ae6ad1243c7d25a5523/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string88 = /40d86b833531b7f216caa95443f4eb6f0e5b15764072a5708d62380bac2f8ff4/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string89 = /46793c55c24e616a0d4eaaa0090b70bdde05e50c1b58da753d09063e6e838cc6/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string90 = /525bb5e67378b9bdc298aceb9e0108603741ae334e8ce748222999fcb2f1d818/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string91 = /534b0370d1bff7e4a0f327d7fa01679a10cfffc67dbefa5f45e49dbbadec7fa3/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string92 = /5ed84b98241dd1db44e9e3beae6ec07ce8c64cd9200b73954617113578f91317/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string93 = /5fa4acad2bf202e61149a7f47189c4d60ac2823ea26d0f449912ab9d28ad0806/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string94 = /66d16546824f6e98b531bfdfe411ba4b837e99362f735ed2dd61ead2aae4ab91/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string95 = /77c88d4c67b3600e78f82c938d2ef72525277647a27692b2114c9688bf1da121/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string96 = /8a575a3e31ecbc724c5b7755ef14a0f645da3cd33ee57f9c91d74b1d94cdf772/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string97 = /925365b64eb63bafba4fb5c44494428026d98c1a71fc4b54d638c4c22c6e26a7/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string98 = /9521883a37c093f31e9d3fde7d3293f637ea51ce573c3fa7967843b7e51d8dd0/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string99 = /9b33e5ff2cc99df282013554ee5cc3a9a0fe737510af24717b48f93c5d66b94a/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string100 = /9c409702151446f1eb8d951b45a902f2dbad1ebeacab9dd9beeaa5530e65ad0c/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string101 = /a10190903dfb52127ae37214a8c0124c68fc2f7fc91d0bae55eb9f556fa3c8dd/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string102 = /a83c33f484a2cbff3bbefdf51880714968930f69778e8921d8182d2b96e03314/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string103 = /abd9f4b93fc3f2bb0612bfbdef4e0da8797e985e7377ee0c08c2b5b5198c2743/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string104 = /Append\sIOC\swatermark\sto\sinjected\sshellcode/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string105 = /b3ae1abc15df71a69f3a629fbe5a168acc7514905d8fd82eb8c62e60f61e846e/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string106 = /Backdoored\sPE\sfile\ssave/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string107 = /be642266\-f34d\-43c3\-b6e4\-eebf8e489519/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string108 = /Binary\-Offensive\/ProtectMyTooling/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string109 = /c39d2a1c303847785a2a2af357dd948f5e6ec8194eb427c52a391db90de34f72/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string110 = /cecbe047e33d2dc3bc06cc7a62546a4e1a793d8da1dde4ba3aa021f944930d6d/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string111 = /d43ceb0d2efb5fdee19d4f7b2448c7f69a6c5d24bfdfd21f5e0fce570fb47d79/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string112 = /d683205c9fad76e28a8e4cd0d72285e9a8573cc95c8b77f30186089459675817/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string113 = /ddcc3057b5c499e1e90d914d9da185d5860f0e9f44a3e5b8f5c9396eaa216ce0/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string114 = /e403c105e8167585b1c431cdc86c943a8f93e876b3940668d088b976d8a1e9a2/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string115 = /e5509a144cb371b7afe6fb6a526fca317688da6b27bfcb7be1faf8fffd58a472/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string116 = /edb161280fe76c89768cab2f9493295671042046f106a7686854f8b5ed118249/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string117 = /ee68d7deb7cefdfca66c078d6036d7aa3aa7afcc62b282999034b4a1faed890d/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string118 = /f109966b6fc1f0ea412a05078baaa79667529be0a387070da7c458a914a07e8e/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string119 = /f487a8b9f72e87a862c6380d316e93dc4bd0a7e7087d6f430e369885db1d5d3d/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string120 = /f80f4c638c843e17f384851f397322eaec414b3718ce79056abc15a6644f466f/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string121 = /hyperion\.exe\s.{0,1000}\.exe.{0,1000}\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string122 = /mgeeky\.tech\/protectmytooling\// nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string123 = /mgeeky\@commandoVM/ nocase ascii wide
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
        $string128 = /Out\-EncodedBXORCommand/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string129 = /Out\-EncodedHexCommand\./ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string130 = /Out\-EncodedOctalCommand\./ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string131 = /Out\-EncodedSpecialCharOnlyCommand/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string132 = /Out\-EncodedWhitespaceCommand/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string133 = /Out\-ObfuscatedArrayExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string134 = /Out\-ObfuscatedArrayLiteralAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string135 = /Out\-ObfuscatedAssignmentStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string136 = /Out\-ObfuscatedAst\.ps1/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string137 = /Out\-ObfuscatedAstsReordered\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string138 = /Out\-ObfuscatedAttributeAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string139 = /Out\-ObfuscatedAttributeBaseAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string140 = /Out\-ObfuscatedAttributedExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string141 = /Out\-ObfuscatedBaseCtorInvokeMemberExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string142 = /Out\-ObfuscatedBinaryExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string143 = /Out\-ObfuscatedBlockStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string144 = /Out\-ObfuscatedBreakStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string145 = /Out\-ObfuscatedCatchClauseAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string146 = /Out\-ObfuscatedChildrenAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string147 = /Out\-ObfuscatedCommandAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string148 = /Out\-ObfuscatedCommandBaseAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string149 = /Out\-ObfuscatedCommandElementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string150 = /Out\-ObfuscatedCommandExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string151 = /Out\-ObfuscatedCommandParameterAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string152 = /Out\-ObfuscatedConfigurationDefinitionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string153 = /Out\-ObfuscatedConstantExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string154 = /Out\-ObfuscatedContinueStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string155 = /Out\-ObfuscatedConvertExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string156 = /Out\-ObfuscatedDataStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string157 = /Out\-ObfuscatedDoUntilStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string158 = /Out\-ObfuscatedDoWhileStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string159 = /Out\-ObfuscatedDynamicKeywordStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string160 = /Out\-ObfuscatedErrorExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string161 = /Out\-ObfuscatedErrorStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string162 = /Out\-ObfuscatedExitStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string163 = /Out\-ObfuscatedExpandableStringExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string164 = /Out\-ObfuscatedExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string165 = /Out\-ObfuscatedFileRedirectionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string166 = /Out\-ObfuscatedForEachStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string167 = /Out\-ObfuscatedForStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string168 = /Out\-ObfuscatedFunctionDefinitionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string169 = /Out\-ObfuscatedFunctionMemberAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string170 = /Out\-ObfuscatedHashtableAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string171 = /Out\-ObfuscatedIfStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string172 = /Out\-ObfuscatedIndexExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string173 = /Out\-ObfuscatedInvokeMemberExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string174 = /Out\-ObfuscatedLabeledStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string175 = /Out\-ObfuscatedLoopStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string176 = /Out\-ObfuscatedMemberAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string177 = /Out\-ObfuscatedMemberExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string178 = /Out\-ObfuscatedMergingRedirectionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string179 = /Out\-ObfuscatedNamedAttributeArgumentAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string180 = /Out\-ObfuscatedNamedBlockAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string181 = /Out\-ObfuscatedParamBlockAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string182 = /Out\-ObfuscatedParameterAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string183 = /Out\-ObfuscatedParenExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string184 = /Out\-ObfuscatedPipelineAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string185 = /Out\-ObfuscatedPipelineBaseAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string186 = /Out\-ObfuscatedPropertyMemberAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string187 = /Out\-ObfuscatedRedirectionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string188 = /Out\-ObfuscatedReturnStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string189 = /Out\-ObfuscatedScriptBlockAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string190 = /Out\-ObfuscatedScriptBlockExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string191 = /Out\-ObfuscatedStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string192 = /Out\-ObfuscatedStatementBlockAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string193 = /Out\-ObfuscatedStringCommand/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string194 = /Out\-ObfuscatedStringConstantExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string195 = /Out\-ObfuscatedSubExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string196 = /Out\-ObfuscatedSwitchStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string197 = /Out\-ObfuscatedThrowStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string198 = /Out\-ObfuscatedTokenCommand/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string199 = /Out\-ObfuscatedTrapStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string200 = /Out\-ObfuscatedTryStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string201 = /Out\-ObfuscatedTypeConstraintAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string202 = /Out\-ObfuscatedTypeDefinitionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string203 = /Out\-ObfuscatedTypeExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string204 = /Out\-ObfuscatedUnaryExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string205 = /Out\-ObfuscatedUsingExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string206 = /Out\-ObfuscatedUsingStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string207 = /Out\-ObfuscatedVariableExpressionAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string208 = /Out\-ObfuscatedWhileStatementAst\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string209 = /Out\-ParenthesizedString\s/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string210 = /packers\/invobf\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string211 = /packers\\invobf\.py/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string212 = /pip\sinstall\sdonut\-shellcode/ nocase ascii wide
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
        $string217 = /upx\s\-\-brute\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string218 = /upx\s\-ultra\-brute\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Multi-Packer wrapper letting us daisy-chain various packers obfuscators and other Red Team oriented weaponry
        // Reference: https://github.com/mgeeky/ProtectMyTooling
        $string219 = /Your\sfinest\sPE\sbackdooring\scompanion/ nocase ascii wide

    condition:
        any of them
}
