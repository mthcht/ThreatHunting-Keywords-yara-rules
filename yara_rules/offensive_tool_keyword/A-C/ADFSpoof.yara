rule ADFSpoof
{
    meta:
        description = "Detection patterns for the tool 'ADFSpoof' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADFSpoof"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A python tool to forge AD FS security tokens.
        // Reference: https://github.com/mandiant/ADFSpoof
        $string1 = /.{0,1000}\sADFSpoof\.py.{0,1000}/ nocase ascii wide
        // Description: A python tool to forge AD FS security tokens.
        // Reference: https://github.com/mandiant/ADFSpoof
        $string2 = /.{0,1000}\s\-b\s.{0,1000}\.bin\s.{0,1000}\.bin\sdump.{0,1000}/ nocase ascii wide
        // Description: A python tool to forge AD FS security tokens.
        // Reference: https://github.com/mandiant/ADFSpoof
        $string3 = /.{0,1000}\/ADFSpoof\.py.{0,1000}/ nocase ascii wide
        // Description: A python tool to forge AD FS security tokens.
        // Reference: https://github.com/mandiant/ADFSpoof
        $string4 = /.{0,1000}\\ADFSpoof\.py.{0,1000}/ nocase ascii wide
        // Description: A python tool to forge AD FS security tokens.
        // Reference: https://github.com/mandiant/ADFSpoof
        $string5 = /.{0,1000}ADFSpoof\-master.{0,1000}/ nocase ascii wide
        // Description: A python tool to forge AD FS security tokens.
        // Reference: https://github.com/mandiant/ADFSpoof
        $string6 = /.{0,1000}EncryptedPfx\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
