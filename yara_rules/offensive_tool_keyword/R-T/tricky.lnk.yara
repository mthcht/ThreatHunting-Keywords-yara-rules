rule tricky_lnk
{
    meta:
        description = "Detection patterns for the tool 'tricky.lnk' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tricky.lnk"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: VBS that creates a .lnk file spoofing the file extension with unicode chars that reverses the .lnk file extension. appends .txt to the end and changes the icon to notepad to make it appear as a textfile. When executed. the payload is a powershell webdl and execute
        // Reference: https://github.com/xillwillx/tricky.lnk
        $string1 = /tricky\.lnk/ nocase ascii wide

    condition:
        any of them
}
