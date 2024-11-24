rule SharpBuster
{
    meta:
        description = "Detection patterns for the tool 'SharpBuster' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpBuster"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string1 = /\sSharpBuster\.dll/ nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string2 = /\sSharpBuster\.exe/ nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string3 = /\s\-u\shttp.{0,100}\s\-\-wordlisturl\s.{0,100}\s\-e\sphp\,aspx\s\-\-recursion\strue/ nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string4 = /\/SharpBuster\.dll/ nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string5 = /\/SharpBuster\.exe/ nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string6 = /\\SharpBuster\.csproj/ nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string7 = /\\SharpBuster\.dll/ nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string8 = /\\SharpBuster\.exe/ nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string9 = /\\SharpBuster\.pdb/ nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string10 = /\\SharpBuster\.sln/ nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string11 = "20ea253cc72883a4744a712d7dc06622b1655b70b4c32d2b74e4f2650919e2ec" nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string12 = "33a6ca1dea55d7cd2edc7d25de16ce7689fcfc7c51fb2f26ebe1a07a3c81c017" nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string13 = "3e475ed049ac5a398735ed67e51fc74e6da81238cb09f0bc1cf0e60d50c37f3d" nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string14 = "62bba0a6ecfaf6e8052504a2699b1ba24822f2098223ba459f83a29ec4f70cf6" nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string15 = "6412cb5d528ee93be2fc08b2c72cdee6c36e38ce5064d2685139bcbf9962298f" nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string16 = "9786E418-6C4A-471D-97C0-8B5F2ED524C8" nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string17 = "a32cdeddc7deb6d2ac210ec304930da4e9c6763975d72685fd7108ad48883715" nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string18 = "cd8e9d2d24021e2a7ef20793d8b26f3c0baa8eea46e927875b53704761117bdd" nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string19 = "cd8e9d2d24021e2a7ef20793d8b26f3c0baa8eea46e927875b53704761117bdd" nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string20 = "f5cc1aeedb6a3e4a927ba5c1029c6075b2b9be7cf517cfdd8277bb0b00b5a60e" nocase ascii wide
        // Description: This is a C# implementation of a directory brute forcing tool designed to allow for in-memory execution
        // Reference: https://github.com/passthehashbrowns/SharpBuster
        $string21 = /SharpBuster\.AssemblyInfo\.cs/ nocase ascii wide
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
