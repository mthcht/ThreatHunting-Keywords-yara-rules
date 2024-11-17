rule KittyStager
{
    meta:
        description = "Detection patterns for the tool 'KittyStager' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KittyStager"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string1 = /\sKittyStager/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string2 = /\/edr\-checker\// nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string3 = /\/getLegit\/cdnl/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string4 = /\/getLegit\/grkg/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string5 = /\/getLegit\/prvw/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string6 = /\/getLegit\/qhwl/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string7 = /\/getLegit\/tsom/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string8 = /\/getLegit\/zijz/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string9 = /\/kittens\/haloKitten/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string10 = /\/kittens\/recycleKitten/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string11 = /\/KittyStager\// nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string12 = /\/postLegit\/grkg/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string13 = /\/postLegit\/qhwl/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string14 = /\/shellcode.{0,100}loader\.bin/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string15 = /\\basicKitten\.exe/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string16 = /\\kitten\.exe/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string17 = /\\KittyStager/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string18 = /127\.0\.0\.1\:1337/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string19 = /505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string20 = /bananaKitten\.exe/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string21 = /dllKitten\.dll/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string22 = /Enelg52\/KittyStager/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string23 = /Invoke\-EDRChecker\.ps1/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string24 = /kitten\.dll/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string25 = /kitten\/basicKitten/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string26 = /kitten_test\.go/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string27 = /kittens\/bananaKitten/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string28 = /KittyStager\s\-/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string29 = /KittyStager\s\?/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string30 = /KittyStager\s\?\?/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string31 = /KittyStager\.git/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string32 = /KittyStager\/cmd/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string33 = /KittyStager\/internal/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string34 = /KittyStager\/kitten/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string35 = /localhost\:1337/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string36 = /malware\.NewConfig/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string37 = /\-o\s\skitten\.exe/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string38 = /output.{0,100}kitten\.exe/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string39 = /shellcode.{0,100}shellcode\.bin/ nocase ascii wide
        // Description: KittyStager is a simple stage 0 C2. It is made of a web server to host the shellcode and an implant called kitten. The purpose of this project is to be able to have a web server and some kitten and be able to use the with any shellcode.
        // Reference: https://github.com/Enelg52/KittyStager
        $string40 = /xzfbmR6MskR8J6Zr58RrhMc325kejLJE/ nocase ascii wide
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
