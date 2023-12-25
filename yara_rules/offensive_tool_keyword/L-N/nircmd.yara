rule nircmd
{
    meta:
        description = "Detection patterns for the tool 'nircmd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nircmd"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string1 = /\.exe\selevatecmd\srunassystem\s/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string2 = /\.exe\sexec\shide\s/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string3 = /nircmdc\.exe\ssavescreenshot/ nocase ascii wide

    condition:
        any of them
}
