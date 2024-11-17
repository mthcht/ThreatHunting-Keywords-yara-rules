rule AutoC2
{
    meta:
        description = "Detection patterns for the tool 'AutoC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string1 = /\sCred_Dump\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string2 = /\sDefense_Evasion\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string3 = /\sExfil\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string4 = /\sHak5\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string5 = /\sPersistence\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string6 = /\sPriv_Esc\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string7 = /\.\/Exfil\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string8 = /\.\/Phishing\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string9 = /\/Cred_Dump\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string10 = /\/Defense_Evasion\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string11 = /\/Hak5\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string12 = /\/opt\/Password_Cracking\// nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string13 = /\/Persistence\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string14 = /\/Phishing\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string15 = /\/Priv_Esc\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string16 = /AutoC2\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string17 = /AutoC2\/All\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string18 = /AutoC2\/C2/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string19 = /AutoC2\/Dependencies/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string20 = /AutoC2\/Initial_Access/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string21 = /AutoC2\/Lateral\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string22 = /AutoC2\/Payload_Development/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string23 = /AutoC2\/Recon/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string24 = /AutoC2\/Situational_Awareness/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string25 = /AutoC2\/Social\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string26 = /AutoC2\/Staging/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string27 = /AutoC2\/Web\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string28 = /AutoC2\/Wireless\.sh/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string29 = /AutoC2\/Wordlists/ nocase ascii wide
        // Description: AutoC2 is a bash script written to install all of the red team tools that you know and love
        // Reference: https://github.com/assume-breach/Home-Grown-Red-Team/tree/main/AutoC2
        $string30 = /Password_Cracking\.sh/ nocase ascii wide
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
