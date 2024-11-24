rule Invoke_s4u2self
{
    meta:
        description = "Detection patterns for the tool 'Invoke-s4u2self' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-s4u2self"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool that abuses s4u2self to gain access to remote hosts
        // Reference: https://github.com/Leo4j/Invoke-s4u2self
        $string1 = /\\Users\\Public\\Documents\\comm\.txt/ nocase ascii wide
        // Description: A tool that abuses s4u2self to gain access to remote hosts
        // Reference: https://github.com/Leo4j/Invoke-s4u2self
        $string2 = "99775a584cbe0d578bfe061143714ca20bf561703c106508642308097c50270a" nocase ascii wide
        // Description: A tool that abuses s4u2self to gain access to remote hosts
        // Reference: https://github.com/Leo4j/Invoke-s4u2self
        $string3 = "Invoke-Rubeus createnetonly" nocase ascii wide
        // Description: A tool that abuses s4u2self to gain access to remote hosts
        // Reference: https://github.com/Leo4j/Invoke-s4u2self
        $string4 = "Invoke-Rubeus s4u" nocase ascii wide
        // Description: A tool that abuses s4u2self to gain access to remote hosts
        // Reference: https://github.com/Leo4j/Invoke-s4u2self
        $string5 = "Invoke-s4u2self" nocase ascii wide

    condition:
        any of them
}
