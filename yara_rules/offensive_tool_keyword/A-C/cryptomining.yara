rule cryptomining
{
    meta:
        description = "Detection patterns for the tool 'cryptomining' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cryptomining"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Linux Cyptomining malware
        // Reference: https://github.com/tarcisio-marinho/cryptomining
        $string1 = /\/cryptomining\.git/
        // Description: A Linux Cyptomining malware
        // Reference: https://github.com/tarcisio-marinho/cryptomining
        $string2 = "/tmp/cryptomining"
        // Description: A Linux Cyptomining malware
        // Reference: https://github.com/tarcisio-marinho/cryptomining
        $string3 = /\[\+\]\sCryptomining\sfolder\screated\!/
        // Description: A Linux Cyptomining malware
        // Reference: https://github.com/tarcisio-marinho/cryptomining
        $string4 = "ca378ad09474b4c41b94590b65d3cdf28cd8e28063f1f9c5aa753f8f1b1ed233"
        // Description: A Linux Cyptomining malware
        // Reference: https://github.com/tarcisio-marinho/cryptomining
        $string5 = "tarcisio-marinho/cryptomining"

    condition:
        any of them
}
