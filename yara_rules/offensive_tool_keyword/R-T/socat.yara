rule socat
{
    meta:
        description = "Detection patterns for the tool 'socat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "socat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: socat is a relay for bidirectional data transfer between two independent data channels. Each of these data channels may be a file. pipe. device
        // Reference: https://github.com/craSH/socat
        $string1 = /.{0,1000}socat\s.{0,1000}/ nocase ascii wide
        // Description: listening on port 1337 -observed in variousmalware and poc explitation tools
        // Reference: N/A
        $string2 = /.{0,1000}socat\stcp4\-listen:1337.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
