rule chashell
{
    meta:
        description = "Detection patterns for the tool 'chashell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chashell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Chashell is a Go reverse shell that communicates over DNS. It can be used to bypass firewalls or tightly restricted networks
        // Reference: https://github.com/sysdream/chashell
        $string1 = /\/chashell\.git/ nocase ascii wide
        // Description: Chashell is a Go reverse shell that communicates over DNS. It can be used to bypass firewalls or tightly restricted networks
        // Reference: https://github.com/sysdream/chashell
        $string2 = /release\/chaserv/ nocase ascii wide
        // Description: Chashell is a Go reverse shell that communicates over DNS. It can be used to bypass firewalls or tightly restricted networks
        // Reference: https://github.com/sysdream/chashell
        $string3 = /release\/chashell_/ nocase ascii wide
        // Description: Chashell is a Go reverse shell that communicates over DNS. It can be used to bypass firewalls or tightly restricted networks
        // Reference: https://github.com/sysdream/chashell
        $string4 = /sysdream\/chashell/ nocase ascii wide

    condition:
        any of them
}
