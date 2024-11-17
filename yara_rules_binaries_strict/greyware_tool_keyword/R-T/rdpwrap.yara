rule rdpwrap
{
    meta:
        description = "Detection patterns for the tool 'rdpwrap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rdpwrap"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string1 = /\sRDPWInst\.exe/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string2 = /\srdpwrap\.dll/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string3 = /\\"\%\~dp0RDPWInst\\"\s\-i\s\-o/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string4 = /\%\~dp0RDPWInst\.exe/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string5 = /\/RDPWInst\.exe/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string6 = /\/RDPWInst\-v.{0,100}\.msi/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string7 = /\/rdpwrap\.dll/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string8 = /\/rdpwrap\.git/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string9 = /\/RDPWrap\-v.{0,100}\.zip/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string10 = /\/res\/rdpwrap\.ini/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string11 = /\\bin\\RDPConf\.exe/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string12 = /\\RDP\sWrapper\\/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string13 = /\\RDPCheck\.exe/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string14 = /\\RDPWInst\.exe/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string15 = /\\RDPWInst\-v.{0,100}\.msi/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string16 = /\\RDPWrap\.cpp/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string17 = /\\rdpwrap\.dll/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string18 = /\\rdpwrap\.ini/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string19 = /\\RDPWrap\.sln/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string20 = /\\rdpwrap\.txt/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string21 = /\\rdpwrap\-master/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string22 = /\\RDPWrapSetup/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string23 = /\\RDPWrap\-v.{0,100}\.zip/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string24 = /1232372059db3ecf28cc2609a36b7f20cef2dfe0618770e3ebaa9488bc7fc2de/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string25 = /29E4E73B\-EBA6\-495B\-A76C\-FBB462196C64/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string26 = /35a9481ddbed5177431a9ea4bd09468fe987797d7b1231d64942d17eb54ec269/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string27 = /3699b102bf5ad1120ef560ae3036f27c74f6161b62b31fda8087bd7ae1496ee1/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string28 = /9899ffecf141ab4535ec702facbf2b4233903b428b862f3a87e635d09c6244de/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string29 = /aaf7e238a5c0bb2a7956e2fdca9b534f227f7b737641962fb0ed965390ace4c6/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string30 = /f9a82873a1e55bb1b5b8b8781b06799ff665464cff8ce77e07474c089123b643/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string31 = /fed08bd733b8e60b5805007bd01a7bf0d0b1993059bbe319d1179facc6b73361/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string32 = /Initializing\sRDP\sWrapper/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string33 = /\'RDP\sWrapper\sLibrary\sInstaller\sv1\.0\'/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string34 = /RDP\sWrapper\\RDPConf/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string35 = /RDPWInst\s\-w/ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string36 = /rdpwrap\\.{0,100}\\RDPWInst\./ nocase ascii wide
        // Description: RDP Wrapper Library used by malwares
        // Reference: https://github.com/stascorp/rdpwrap
        $string37 = /stascorp\/rdpwrap/ nocase ascii wide
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
