rule powercat
{
    meta:
        description = "Detection patterns for the tool 'powercat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powercat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string1 = /\s\-l\s\-p\s.{0,1000}\s\-e\scmd\s\-ge/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string2 = /\spowercat\.ps1/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string3 = /\.ps1\s\-l\s\-p\s.{0,1000}\s\-r\sdns\:\:\:/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string4 = /\/powercat\.git/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string5 = /\/powercat\.ps1/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string6 = /\\powercat\.ps1/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string7 = /\\powercat\-master\\/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string8 = /79acacd2433990d8fe71ee9583123240b34ae26f4913d62b796238f4a302e104/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string9 = /besimorhino\/powercat/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string10 = /powercat\s\-c\s/ nocase ascii wide
        // Description: Netcat - The powershell version
        // Reference: https://github.com/besimorhino/powercat
        $string11 = /powercat\s\-l\s/ nocase ascii wide

    condition:
        any of them
}
