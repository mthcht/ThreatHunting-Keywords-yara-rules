rule _7zip
{
    meta:
        description = "Detection patterns for the tool '7zip' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "7zip"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: 7zip command to zip results from adfind scans. attackers perform Active Directory collection using AdFind in batch scriptsfrom C:\Windows\Temp\adf\ or C:\temp\ and store output in CSV files
        // Reference: http://www.joeware.net/freetools/tools/adfind/index.htm
        $string1 = /7\.exe\sa\s\-mx3\sad\.7z\sad_.{0,1000}\.txt/ nocase ascii wide

    condition:
        any of them
}
