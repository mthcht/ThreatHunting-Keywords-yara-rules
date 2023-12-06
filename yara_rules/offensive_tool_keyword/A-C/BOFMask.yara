rule BOFMask
{
    meta:
        description = "Detection patterns for the tool 'BOFMask' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BOFMask"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BOFMask is a proof-of-concept for masking Cobalt Strike's Beacon payload while executing a Beacon Object File (BOF)
        // Reference: https://github.com/passthehashbrowns/BOFMask
        $string1 = /\/BOFMask\.git/ nocase ascii wide
        // Description: BOFMask is a proof-of-concept for masking Cobalt Strike's Beacon payload while executing a Beacon Object File (BOF)
        // Reference: https://github.com/passthehashbrowns/BOFMask
        $string2 = /\/bofmask\.h/ nocase ascii wide
        // Description: BOFMask is a proof-of-concept for masking Cobalt Strike's Beacon payload while executing a Beacon Object File (BOF)
        // Reference: https://github.com/passthehashbrowns/BOFMask
        $string3 = /BOFMask\-main/ nocase ascii wide
        // Description: BOFMask is a proof-of-concept for masking Cobalt Strike's Beacon payload while executing a Beacon Object File (BOF)
        // Reference: https://github.com/passthehashbrowns/BOFMask
        $string4 = /include.{0,1000}bofmask\.h/ nocase ascii wide
        // Description: BOFMask is a proof-of-concept for masking Cobalt Strike's Beacon payload while executing a Beacon Object File (BOF)
        // Reference: https://github.com/passthehashbrowns/BOFMask
        $string5 = /passthehashbrowns\/BOFMask/ nocase ascii wide

    condition:
        any of them
}
