rule crowbar
{
    meta:
        description = "Detection patterns for the tool 'crowbar' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crowbar"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string1 = /\/crowbar\.git/ nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string2 = /\/crowbar_1\.0\.0_darwin_386\.zip/ nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string3 = /\/crowbar_1\.0\.0_darwin_amd64\.zip/ nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string4 = /\/crowbar_1\.0\.0_freebsd_386\.zip/ nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string5 = /\/crowbar_1\.0\.0_freebsd_amd64\.zip/ nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string6 = /\/crowbar_1\.0\.0_freebsd_arm\.zip/ nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string7 = /\/crowbar_1\.0\.0_linux_386\.tar\.gz/ nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string8 = /\/crowbar_1\.0\.0_linux_amd64\.tar\.gz/ nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string9 = /\/crowbar_1\.0\.0_linux_arm\.tar\.gz/ nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string10 = /\/crowbar_1\.0\.0_openbsd_386\.zip/ nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string11 = /\/crowbar_1\.0\.0_openbsd_amd64\.zip/ nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string12 = /\/crowbar_1\.0\.0_windows_386\.zip/ nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string13 = /\/crowbar_1\.0\.0_windows_amd64\.zip/ nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string14 = "/etc/crowbar/" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string15 = /\/etc\/crowbard\.conf/ nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string16 = "47e4818c3db3471c950cdb4c4732232bafc584997098c92ada8a0f720e2ad448" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string17 = "4ba042e8f3a3f5cf7e01e64461d27f5733c505b8a0f221fb91ed44e93627cd91" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string18 = "4df132ced0bbdbe4965bea528bb11385426a938fcdec3a2905b92d800c9c8fba" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string19 = "515983df3a9aad4aae1e5e37cdf489686b4d7daed5610a75d75ebba006c4ddc9" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string20 = "602b348fd6e3407423330d761b04dfdcd8094e552c1184db100c07058343f8d4" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string21 = "6510e91b5511a68222bade46531b5d70850559b7da4dadd2fb187015cc811efa" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string22 = "8c39d2ef5bd7cb5c7aae4c5094f50cbd39b2a6c3fe65a049c91f7943f679d6b9" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string23 = "91bc0b2cabb6618b228003f1f7f4467b1867eae3c3f42081ee8c4e30e937e77e" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string24 = "9bfd1f0cb077ba95935c260cf66554142867486a42c8d84920e09dd3c6117ed1" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string25 = "b4bed3b73a07c019ea853ee051e35932c97a1547809697dfa495a00710dec8eb" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string26 = "chown crowbar:crowbar " nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string27 = "cmd/crowbard/" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string28 = "crowbar-forward -local=" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string29 = "e4d2ed3af31f30f40f83a73dd6c4dcce275ae8cc85d52c7f30a51bfdb7ebeec2" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string30 = "eb459c0af8c8d7bb91f7c6acc4682f1b2a6add840925bc8a9321c5cc1e2a8137" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string31 = "f154878288857410353e4cabc498941869ffbbd1783f6a1923c6ed92c03dfab6" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string32 = "fc81435479e432562efbbb8ed75a397b565d70593af843bb1ac89628132c7ef7" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string33 = "q3k/crowbar" nocase ascii wide
        // Description: Tunnel TCP over a plain HTTP session
        // Reference: https://github.com/q3k/crowbar
        $string34 = "useradd -rm crowbar" nocase ascii wide
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
