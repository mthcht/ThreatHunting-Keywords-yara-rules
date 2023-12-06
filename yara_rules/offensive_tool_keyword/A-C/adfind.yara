rule adfind
{
    meta:
        description = "Detection patterns for the tool 'adfind' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfind"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: attackers perform Active Directory collection using AdFind in batch scripts from C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string1 = /adfind\.exe\s\-f\s\(objectcategory\=organizationalUnit\)\s\>\s.{0,1000}\.txt/ nocase ascii wide
        // Description: attackers perform Active Directory collection using AdFind in batch scripts from C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string2 = /adfind\.exe\s\-f\s\(objectcategory\=person\)\s\>\s.{0,1000}\.txt/ nocase ascii wide
        // Description: attackers perform Active Directory collection using AdFind in batch scripts from C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string3 = /adfind\.exe\s\-f\s.{0,1000}\(objectcategory\=group\).{0,1000}\s\>\s.{0,1000}\.txt/ nocase ascii wide
        // Description: attackers perform Active Directory collection using AdFind in batch scripts from C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string4 = /adfind\.exe\s\-f\sobjectcategory\=computer\s\>\s.{0,1000}\.txt/ nocase ascii wide
        // Description: attackers perform Active Directory collection using AdFind in batch scripts from C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string5 = /adfind\.exe\s\-gcb\s\-sc\strustdmp\s\>\s.{0,1000}\.txt/ nocase ascii wide
        // Description: attackers perform Active Directory collection using AdFind in batch scripts from C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string6 = /adfind\.exe\s\-subnets\s\-f\s\(objectCategory\=subnet\)\s\>\s.{0,1000}\.txt/ nocase ascii wide

    condition:
        any of them
}
