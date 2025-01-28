rule chgpass
{
    meta:
        description = "Detection patterns for the tool 'chgpass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chgpass"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: reset the local administrator password
        // Reference: https://x.com/decoder_it/status/1882851589352051144
        $string1 = /chgpass\.exe.{0,1000}Administrator\s/ nocase ascii wide
        // Description: reset the DSRM password which is the local administrator account on the domain controller stored in the local SAM
        // Reference: https://x.com/decoder_it/status/1882851589352051144
        $string2 = /chgpass\.exe.{0,1000}DSRM/ nocase ascii wide

    condition:
        any of them
}
