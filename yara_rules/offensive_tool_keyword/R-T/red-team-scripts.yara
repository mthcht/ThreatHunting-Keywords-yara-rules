rule red_team_scripts
{
    meta:
        description = "Detection patterns for the tool 'red-team-scripts' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "red-team-scripts"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands (i.e. no Powershell. binary calls. or process injection). Additionally. adds a basic enumerate alias for Linux based systems in SSH sessions.
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string1 = /enumerate\.cna/ nocase ascii wide
        // Description: script comprised of multiple system enumeration / situational awareness techniques collected over time. If system is a member of a Windows domain. it can also perform limited domain enumeration with the -Domain switch
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string2 = /HostEnum\.ps1/ nocase ascii wide
        // Description: script comprised of multiple system enumeration / situational awareness techniques collected over time. If system is a member of a Windows domain. it can also perform limited domain enumeration with the -Domain switch
        // Reference: https://github.com/threatexpress/red-team-scripts
        $string3 = /Invoke\-HostEnum/ nocase ascii wide

    condition:
        any of them
}
