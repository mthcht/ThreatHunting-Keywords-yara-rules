rule lnkbomb
{
    meta:
        description = "Detection patterns for the tool 'lnkbomb' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lnkbomb"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Malicious shortcut generator for collecting NTLM hashes from insecure file shares.
        // Reference: https://github.com/dievus/lnkbomb
        $string1 = /\slnkbomb\.py/ nocase ascii wide
        // Description: Malicious shortcut generator for collecting NTLM hashes from insecure file shares.
        // Reference: https://github.com/dievus/lnkbomb
        $string2 = /\/lnkbomb\.git/ nocase ascii wide
        // Description: Malicious shortcut generator for collecting NTLM hashes from insecure file shares.
        // Reference: https://github.com/dievus/lnkbomb
        $string3 = /\/lnkbomb\.py/ nocase ascii wide
        // Description: Malicious shortcut generator for collecting NTLM hashes from insecure file shares.
        // Reference: https://github.com/dievus/lnkbomb
        $string4 = /\[warn\]\sYou\seither\sfat\sfingered\sthis\sor\ssomething\selse\.\sEither\sway/ nocase ascii wide
        // Description: Malicious shortcut generator for collecting NTLM hashes from insecure file shares.
        // Reference: https://github.com/dievus/lnkbomb
        $string5 = /\\lnkbomb\.py/ nocase ascii wide
        // Description: Malicious shortcut generator for collecting NTLM hashes from insecure file shares.
        // Reference: https://github.com/dievus/lnkbomb
        $string6 = /\\lnkbomb\-1\.0\\/ nocase ascii wide
        // Description: Malicious shortcut generator for collecting NTLM hashes from insecure file shares.
        // Reference: https://github.com/dievus/lnkbomb
        $string7 = /dievus\/lnkbomb/ nocase ascii wide
        // Description: Malicious shortcut generator for collecting NTLM hashes from insecure file shares.
        // Reference: https://github.com/dievus/lnkbomb
        $string8 = /lnkbomb\.py\s/ nocase ascii wide
        // Description: Malicious shortcut generator for collecting NTLM hashes from insecure file shares.
        // Reference: https://github.com/dievus/lnkbomb
        $string9 = /lnkbomb\-1\.0\.zip/ nocase ascii wide
        // Description: Malicious shortcut generator for collecting NTLM hashes from insecure file shares.
        // Reference: https://github.com/dievus/lnkbomb
        $string10 = /Malicious\sShortcut\sGenerator/ nocase ascii wide

    condition:
        any of them
}
