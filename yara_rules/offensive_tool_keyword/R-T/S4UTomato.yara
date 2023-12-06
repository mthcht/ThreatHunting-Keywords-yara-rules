rule S4UTomato
{
    meta:
        description = "Detection patterns for the tool 'S4UTomato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "S4UTomato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string1 = /\.exe\skrbscm\s\-c\s.{0,1000}cmd\.exe/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string2 = /\.exe\srbcd\s\-m\s.{0,1000}\s\-p\s.{0,1000}\s\-c\s.{0,1000}cmd\.exe/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string3 = /\.exe\sshadowcred\s\-c\s.{0,1000}\s\-f/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string4 = /\/S4UTomato\.git/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string5 = /881D4D67\-46DD\-4F40\-A813\-C9D3C8BE0965/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string6 = /Run\sthe\skrbscm\smethod\sfor\sSYSTEM\sshell/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string7 = /S4UTomato\s1\.0\.0\-beta/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string8 = /S4UTomato\.csproj/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string9 = /S4UTomato\.exe/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string10 = /S4UTomato\.sln/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string11 = /S4UTomato\-master/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string12 = /wh0amitz\/S4UTomato/ nocase ascii wide

    condition:
        any of them
}
