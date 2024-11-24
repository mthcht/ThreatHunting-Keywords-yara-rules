rule tunwg
{
    meta:
        description = "Detection patterns for the tool 'tunwg' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tunwg"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string1 = /\stunwg\.exe/ nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string2 = /\.\/tunwg\s\-\-/ nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string3 = /\.l\.tunwg\.com/ nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string4 = "/bin/tunwg" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string5 = "/latest/download/tunwg" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string6 = /\/tunwg\.exe/ nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string7 = /\/tunwg\.git/ nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string8 = "/tunwg@latest" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string9 = /\/tunwg\-arm64\.exe/ nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string10 = /\\tunwg\.exe/ nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string11 = /\\tunwg\-arm64\.exe/ nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string12 = "067fca2b141364d273b05e14a8f01d961d80d9599b8658a02a4f486510b9b89b" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string13 = "0f1ccf4c5e7eada818bafad12e911a4d122a8329f7287ea0e4903ee1398e72f9" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string14 = "175c54eb22bc4eeb089586244b2863d53e14fbe8be999be5574901aa0a726744" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string15 = "2664814fc6bac015389cad412970cb6617f38a653f30585060c158f4d7963527" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string16 = "2cf91adccb7872c4e0526ac1b4c5d9ccb539dcd9f3c2c85daba0837fb2483e2b" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string17 = "3451e50cf07aa0e206cc3a632482276574f820542860187ffb8ec2221453a875" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string18 = "393d1d4e9992cbda5a9980c25d9d16890b18f276fc08a44c5855b3a14f4be894" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string19 = "3a52dc3df7ea98057fb163965ed3390702a95a57e8b4e5e263c7efeb83908577" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string20 = "3bcd2aa02fed9aad200636add540ac159c082eb6058a9da45ed0dc7410713f38" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string21 = "574583d2e4b8f71d7aa57ed24c4015e37bdfe937bcd7f0d708f300eac9bc33e2" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string22 = "6d7d84fd5a11387aa706ed690f5855893594d5ded8ddeaf49cb449927c071f5f" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string23 = "72b86dc356b7f6708f1996cf2085fd66a75d05e04ab728c245db5d660f645281" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string24 = "8d3cb4cbaa6643fd38caec3505f0541a56883504a65759e38e8a9e8764a5f4c7" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string25 = "9e66f8414c42c546b1d73672929a13285681ab0862f8ed9aa75d048dd5aa00e7" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string26 = "a8ea3cb39c602716d396076e7621a61e3df77e4e08377f33c6aebf4cc970f26c" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string27 = "b46ed003967f739acb4f0778b4665dc9aceab652c51223b10f632ab0681b7261" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string28 = /certs\@tunwg\.com/ nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string29 = "d0d4347afb60b25e067af0d693c644b76560164c793304e35af765d023c14df6" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string30 = "ddc7e4a39c307d93871a3198d2e888e697a0106b5ebc7002e9361d0f49ba2b21" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string31 = "e105000f9beb2d9659ead318f0f8a9a3acf90606024c5eef2fe11a4d140c4ee2" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string32 = "e750475e2594a84524d937f7ee405611f4237851d4a8d119f4d41b6127d2aa82" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string33 = "ea46f4c9b2aacf0628d9410efe46c2a625eaf7a1b9a1a017e5547a5361062985" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string34 = /https\:\/\/tunwg\.com/ nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string35 = "ntnj/tunwg" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string36 = "tunwg --forward" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string37 = "tunwg -p " nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string38 = /tunwg.{0,100}wireguard\.go/ nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string39 = "tunwg: initiating handshake to server" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string40 = "TUNWG_IP=" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string41 = "TUNWG_RELAY" nocase ascii wide
        // Description: End to end encrypted secure tunnel to local servers
        // Reference: https://github.com/ntnj/tunwg
        $string42 = "TUNWG_RUN_SERVER" nocase ascii wide
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
