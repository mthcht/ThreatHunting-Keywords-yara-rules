rule lnk2pwn
{
    meta:
        description = "Detection patterns for the tool 'lnk2pwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lnk2pwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Malicious Shortcut(.lnk) Generator
        // Reference: https://github.com/it-gorillaz/lnk2pwn
        $string1 = /\/lnk2pwn\.git/ nocase ascii wide
        // Description: Malicious Shortcut(.lnk) Generator
        // Reference: https://github.com/it-gorillaz/lnk2pwn
        $string2 = /\/lnk2pwn\-1\.0\.0\.zip/ nocase ascii wide
        // Description: Malicious Shortcut(.lnk) Generator
        // Reference: https://github.com/it-gorillaz/lnk2pwn
        $string3 = /\\Lnk2Pwn\.java/ nocase ascii wide
        // Description: Malicious Shortcut(.lnk) Generator
        // Reference: https://github.com/it-gorillaz/lnk2pwn
        $string4 = /\\Lnk2PwnFrame\.java/ nocase ascii wide
        // Description: Malicious Shortcut(.lnk) Generator
        // Reference: https://github.com/it-gorillaz/lnk2pwn
        $string5 = /\\lnk2pwn\-master/ nocase ascii wide
        // Description: Malicious Shortcut(.lnk) Generator
        // Reference: https://github.com/it-gorillaz/lnk2pwn
        $string6 = /\\uac_bypass\.vbs/ nocase ascii wide
        // Description: Malicious Shortcut(.lnk) Generator
        // Reference: https://github.com/it-gorillaz/lnk2pwn
        $string7 = /10c9d70217e5a3915a6c09feea4110991dae5d9a1b6ae5d32c4d69dd6b6eaf50/ nocase ascii wide
        // Description: Malicious Shortcut(.lnk) Generator
        // Reference: https://github.com/it-gorillaz/lnk2pwn
        $string8 = /7bc9e0e60db343690d6dcb61dd7f19c69fbd154234cbc38f7631f4a4a75fca8c/ nocase ascii wide
        // Description: Malicious Shortcut(.lnk) Generator
        // Reference: https://github.com/it-gorillaz/lnk2pwn
        $string9 = /98aa8eec1bda59ea57693a6312bae2b76b2e71dd29cd0f85453c3d867ec69394/ nocase ascii wide
        // Description: Malicious Shortcut(.lnk) Generator
        // Reference: https://github.com/it-gorillaz/lnk2pwn
        $string10 = /com\.itgorillaz\.lnk2pwn\.model/ nocase ascii wide
        // Description: Malicious Shortcut(.lnk) Generator
        // Reference: https://github.com/it-gorillaz/lnk2pwn
        $string11 = /d1fccb8acadbdefaf27f8680c74c40dba94e52734dd9704d38c0de7b10066f14/ nocase ascii wide
        // Description: Malicious Shortcut(.lnk) Generator
        // Reference: https://github.com/it-gorillaz/lnk2pwn
        $string12 = /it\-gorillaz\/lnk2pwn/ nocase ascii wide
        // Description: Malicious Shortcut(.lnk) Generator
        // Reference: https://github.com/it-gorillaz/lnk2pwn
        $string13 = /Malicious\sShortcut\(\.lnk\)\sGenerator/ nocase ascii wide
        // Description: Malicious Shortcut(.lnk) Generator
        // Reference: https://github.com/it-gorillaz/lnk2pwn
        $string14 = /UACBypassConfig\.java/ nocase ascii wide

    condition:
        any of them
}
