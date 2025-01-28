rule lsassy
{
    meta:
        description = "Detection patterns for the tool 'lsassy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lsassy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string1 = " - Remote lsass dump reader" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string2 = /\scomsvcs_stealth\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string3 = /\sDEL\s\{\}SQLDmpr.{0,100}\.mdmp\s\&\sfor\s\/f\s/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string4 = /\sdllinject\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string5 = " dump --usermode --kernelmode --driver " nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string6 = /\sdumpert\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string7 = /\s\-\-dump\-name\s.{0,100}lsass/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string8 = /\s\-fullmemdmp\s\-snap\s\&\sping\s127\.0\.0\.1\s\-n\s/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string9 = /\simpacketfile\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string10 = " lsassy" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string11 = /\srawrpc_embedded\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string12 = /\sSQLDmpr0001\.mdmp/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string13 = /\/\.config\/lsassy/
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string14 = /\/comsvcs_stealth\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string15 = /\/dllinject\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string16 = /\/dumpert\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string17 = /\/dumpmethod\/.{0,100}\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string18 = /\/impacketfile\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string19 = "/lsassy" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string20 = "/lsassy/releases/download/" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string21 = /\/rawrpc\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string22 = /\/rawrpc_embedded\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string23 = /\/silentprocessexit\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string24 = /\/tmp\/credentials\.txt/
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string25 = "/tmp/kerberos_tickets"
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string26 = /\\comsvcs_stealth\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string27 = /\\dllinject\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string28 = /\\dumpert\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string29 = /\\impacketfile\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string30 = /\\rawrpc_embedded\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string31 = /\\temp\\lsass\.exe/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string32 = "049ab1e5eef6dbfb0cfe81f8eac287d82db549369edf2992916d9c8109528159" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string33 = "0bed6254a9818d22f531a9433f9b20d31eefe0550ece4ba12f4e05e8db5c2cfb" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string34 = "0e3c7a01a06f011d9bb7e184d4713f88bbb3def0118e70e2f58ca79966b7c067" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string35 = "16df73e36a53fb2a7c2a022c36d999a853c3e616ae4de7c3633a8d7769e81ec5" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string36 = "216767025356ffaa54815bf698254810253efcd10feddfab82e7f6ed991d553c" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string37 = "21870c033ee041fa83e39818f3f23a51c1f994344f15f1f2b95912c013ad77ff" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string38 = "21db0a4b79dc31e1a31251fd69d793e6dd4839e3a869093f8abd8bc10aa4b7fb" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string39 = "221986c87ed18ec810267b11b919766d2d556127d9a4f2b16f544b39a32c8573" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string40 = "22df0e3fcbba509c1e28a0df720e8a36b62f731ee3bf6066dbd2d6ed09592052" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string41 = "2dc0932b1ec1f7be50038ddcfc69790ff8b8db824d0121a02aad709a9a92119f" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string42 = "31a97e6377d69a3ae7974a441d52657d200210087bfcac7f0c4f79dddf9f488b" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string43 = "37754362c1524cbecc907a1cde4a3c4e1c747235a140c2275e482724fca9955d" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string44 = "3a7f12e2da6e68b00f1a0aff9b515e7c623da2304f729ed756e01582ddfb62aa" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string45 = "3f0aaab9ed83635ff24bf9664603d16e9130183bdb15f55dd02b92d760a97833" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string46 = "417f4c1ad7f0f15d3c01d4930cc583330eb93cf71593c8d872b65a2a50cbb6fc" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string47 = "4841539dd633e3c38767c9098481406113d80aba6c23e5326f30e5328ac30234" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string48 = "4bb963704e0b986784a5d5b1ad7cc6daffc7e062fedf0025df4974e8b0478602" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string49 = "51fecfd2da4eb46257e94548af984f53d88be1e8d476ef0bc64a801588dbb6b5" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string50 = "580ec64c62709841ca04ba73473f1e8681fde57ebbbbb81d1fe12b075b263057" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string51 = "5a9b8cfd138823a0d9799afc9eb70f28ec2ede90a1db1fde81d8bd70e5613fba" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string52 = "5aaed5c8657383a894443a92a259182d9dc2c01de72a80460fff4a636e20c65b" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string53 = "78177028fe6c048b40b90f696adfdcbcbda0a7c9f678125bbead5b4f116098fc" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string54 = "7971e955309e5158aa13fe774596224af88ae64e53f09bd2ffb863acbf88864a" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string55 = "7eb2d2b7d0eaf25f822afa65e9887683ad2c1dd48c2cc447a76a6526222acf06" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string56 = "8560ec462441496a3bd6b0266ed1b023cdb1870a190aaa9dbb34ffcc6e6dd281" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string57 = "87582936adeabd882de92613193a3fefdc2d388238a7c67c3bb41666ac3b2dda" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string58 = "8b5b0e03d4d5becb309f86a7149dd0573f89c19bcd4f8becb7d86b17c90a6c04" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string59 = "8bc52fc1dbd2e9319241d826b23a227132199b37951c8222c901b6ab069c4084" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string60 = "9aeafd043bc6edebba1acbf6f457a63be0edd623899f6245b71ac2e7ba61e03d" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string61 = "9c08b2701019c0b4860a85af161c64c303400d720c494aaeade5c2d0d2607118" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string62 = "b3d7df3faa7bbeddf70a0c3cb586ce3d38aa1bfd787da67dd2338ec72a27bb74" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string63 = "b9d705378ce1af446cc51bbbeccdda2d05bbc6b3c9249f3b69661d5f763dafaa" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string64 = "bad0968b9492c3161ea9b67ecf8520054f90e6d196a7ea0050c8076b2ed2d2a2" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string65 = "c7b633d9ffcddd84074219649dae082184e2331c07b395db5e2ffa9abe316355" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string66 = "cb8f501c3b38552612b6303dfec0479df31b9c79a5fbec5462614f9a1d7eba67" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string67 = "cc8ca4e1e0d6613bd6f040f098f59ff05cea4b9ca74262ec7319ce9846e51a6e" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string68 = "d583e8ee91ab53e8c797b3beb22bfb8b9e775f88436798225e2ec361832a8942" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string69 = "d9e58e0a47eacc9ccb42322516dcd21658aedb39e1dd64ff4af86e4fca648ddc" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string70 = /dllinject\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string71 = /dump_lsass\(/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string72 = /dumpert\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string73 = "dumpert_path=" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string74 = "dumpertdll" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string75 = /dumpertdll\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string76 = "e71c92b2228f78010d91f373ea3c1ed474c0b6298c3b9615edf9edb42be35abb" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string77 = "e82a6a97f9239b0e6bd68c9ce795dc7ae29f6e008bfb8ab63f2dfe9e94817bea" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string78 = /edrsandblast\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string79 = "faf7eccc7aa509a6ac4b65b15e5bd91101a21ec9dd519b9917e7f0ce5f9191e5" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string80 = "ff7db32d94ef4b9e11ced9226a8e4a62eb0ec932e66b4655b845dd7f717bf94a" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string81 = /for\s\/f\s\\"\\"tokens\=2\sdelims\=\s\\"\\"\s\%.{0,100}tasklist\s\/fi\s\\"\\"Imagename\seq\slsass\.exe/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string82 = /hackndo\@gmail\.com/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string83 = /https\:\/\/en\.hackndo\.com\/remote\-lsass\-dump\-passwords\// nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string84 = /impacketfile\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string85 = "login-securite/lsassy" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string86 = "login-securite/lsassy" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string87 = "lsassy " nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string88 = /lsassy\./ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string89 = /lsassy\.impacketfile/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string90 = "lsassy/dumpmethod" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string91 = "lsassy_linux_amd64"
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string92 = /lsassy_logger\./ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string93 = "lsassy_windows_amd64" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string94 = "lsassy-linux-x64-"
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string95 = "lsassy-MacOS-x64-" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string96 = /lsassy\-windows\-latest\.zip/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string97 = /lsassy\-windows\-x64\-.{0,100}\.exe/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string98 = "-m dumpert " nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string99 = /mirrordump\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string100 = /nanodump\./ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string101 = "nanodump_ssp" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string102 = /nanodump_ssp_embedded\./ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string103 = "pip install lsassy" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string104 = /ppldump\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string105 = "ppldump_embedded" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string106 = "procdump_embedded" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string107 = "procdump_path=" nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string108 = /rdrleakdiag\.exe\s\-p\s\(Get\-Process\slsass\)/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string109 = /rdrleakdiag\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string110 = /smb_stealth\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string111 = /sqldumper\.py/ nocase ascii wide
        // Description: Extract credentials from lsass remotely
        // Reference: https://github.com/login-securite/lsassy
        $string112 = /test_lsassy\./ nocase ascii wide
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
