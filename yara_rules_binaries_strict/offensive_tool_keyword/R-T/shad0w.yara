rule shad0w
{
    meta:
        description = "Detection patterns for the tool 'shad0w' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shad0w"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string1 = /\sshad0w\.py/ nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string2 = /\/exploit\.exe/ nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string3 = "/modules/windows/shinject/" nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string4 = /\/shad0w\.deb/ nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string5 = /\/shad0w\.py/ nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string6 = /\/shad0w\.scr/ nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string7 = /\/shad0w\/beacon\/beacon\.dll/ nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string8 = /\/sharpsocks\.log/ nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string9 = /\/SharpSocksServerCore\.dll/ nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string10 = "/usr/bin/shad0w" nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string11 = /\[\+\]\sGot\sSystem\!\!\!\\n/ nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string12 = /\\barnofoo\\pipe\\spoolss/ nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string13 = /\\exploit\.exe/ nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string14 = /\\foobar123\\pipe\\spoolss/ nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string15 = /\\shad0w\.py/ nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string16 = /\\shad0w\.scr/ nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string17 = /\\SharpSocksServerCore\.dll/ nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string18 = "196fdd20e7b602c3b86450e6d4da311618509d31fd3be0af50dee8bd76a5130c" nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string19 = "299c9eda11e70fdd9a0073ae0e45c6e2d8aee617eabd8ed6fb13adc8a890b674" nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string20 = "2ad2ad0002ad2ad00042d42d000000ad9bf51cc3f5a1e29eecb81d0c7b06eb" nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string21 = "8002519fb85548854d30580a8db65ccd4624ce284d13230ad8b3e6366c8f093a" nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string22 = "99a69aea8e1d16454978e00c72b8cf8515faff75c5ffa3f42bc28ee0d51b1252" nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string23 = "b2bb856a232072bbf9dc478fdb3a0fbdf394057ce255ab586d8ea7e34fa2abc0" nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string24 = "d0179fd6daffa7343ce3aebdfb00921c9a69e26cadc61d2f1514e8515c5119ce" nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string25 = "d4f8316d0dd8355a0b857cae8f6fd0a6b3edb3603dc154d30b3aefcc8530baad" nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string26 = "e4d484d9bac7434247fff0c298b8af6b681fa6b140b573d8ce78b1f3bed94e6b" nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string27 = /shad0w\.beacons\.keys/ nocase ascii wide
        // Description: A post exploitation framework designed to operate covertly on heavily monitored environments
        // Reference: https://github.com/bats3c/shad0w
        $string28 = /SharpSocksServer\.Sh/ nocase ascii wide
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
