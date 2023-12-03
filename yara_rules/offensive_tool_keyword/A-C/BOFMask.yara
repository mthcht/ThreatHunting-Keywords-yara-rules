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
        $string1 = /.{0,1000}\/BOFMask\.git.{0,1000}/ nocase ascii wide
        // Description: BOFMask is a proof-of-concept for masking Cobalt Strike's Beacon payload while executing a Beacon Object File (BOF)
        // Reference: https://github.com/passthehashbrowns/BOFMask
        $string2 = /.{0,1000}\/bofmask\.h.{0,1000}/ nocase ascii wide
        // Description: BOFMask is a proof-of-concept for masking Cobalt Strike's Beacon payload while executing a Beacon Object File (BOF)
        // Reference: https://github.com/passthehashbrowns/BOFMask
        $string3 = /.{0,1000}BOFMask\-main.{0,1000}/ nocase ascii wide
        // Description: BOFMask is a proof-of-concept for masking Cobalt Strike's Beacon payload while executing a Beacon Object File (BOF)
        // Reference: https://github.com/passthehashbrowns/BOFMask
        $string4 = /.{0,1000}include.{0,1000}bofmask\.h.{0,1000}/ nocase ascii wide
        // Description: BOFMask is a proof-of-concept for masking Cobalt Strike's Beacon payload while executing a Beacon Object File (BOF)
        // Reference: https://github.com/passthehashbrowns/BOFMask
        $string5 = /.{0,1000}passthehashbrowns\/BOFMask.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
