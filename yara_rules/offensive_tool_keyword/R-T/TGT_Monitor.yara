rule TGT_Monitor
{
    meta:
        description = "Detection patterns for the tool 'TGT_Monitor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TGT_Monitor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This script continuously monitors cache for new TGTs and displays them on the screen (admin privs required)
        // Reference: https://github.com/Leo4j/TGT_Monitor
        $string1 = /\sTGT_Monitor\.ps1/ nocase ascii wide
        // Description: This script continuously monitors cache for new TGTs and displays them on the screen (admin privs required)
        // Reference: https://github.com/Leo4j/TGT_Monitor
        $string2 = /\/TGT_Monitor\.git/ nocase ascii wide
        // Description: This script continuously monitors cache for new TGTs and displays them on the screen (admin privs required)
        // Reference: https://github.com/Leo4j/TGT_Monitor
        $string3 = /\/TGT_Monitor\.ps1/ nocase ascii wide
        // Description: This script continuously monitors cache for new TGTs and displays them on the screen (admin privs required)
        // Reference: https://github.com/Leo4j/TGT_Monitor
        $string4 = /\\TGT_Monitor\.ps1/ nocase ascii wide
        // Description: This script continuously monitors cache for new TGTs and displays them on the screen (admin privs required)
        // Reference: https://github.com/Leo4j/TGT_Monitor
        $string5 = /1004ed17f2164c6dd249f7d640e8c8250e6c47d9e4d2c8748becb05591a8539b/ nocase ascii wide
        // Description: This script continuously monitors cache for new TGTs and displays them on the screen (admin privs required)
        // Reference: https://github.com/Leo4j/TGT_Monitor
        $string6 = /Get\-AesKeyFromPassphrase/ nocase ascii wide
        // Description: This script continuously monitors cache for new TGTs and displays them on the screen (admin privs required)
        // Reference: https://github.com/Leo4j/TGT_Monitor
        $string7 = /Leo4j\/TGT_Monitor/ nocase ascii wide
        // Description: This script continuously monitors cache for new TGTs and displays them on the screen (admin privs required)
        // Reference: https://github.com/Leo4j/TGT_Monitor
        $string8 = /TGT_Monitor\s\-EncryptionKey\s/ nocase ascii wide

    condition:
        any of them
}
