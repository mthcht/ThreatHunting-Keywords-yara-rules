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
        $string1 = /.{0,1000}\.exe\skrbscm\s\-c\s.{0,1000}cmd\.exe.{0,1000}/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string2 = /.{0,1000}\.exe\srbcd\s\-m\s.{0,1000}\s\-p\s.{0,1000}\s\-c\s.{0,1000}cmd\.exe.{0,1000}/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string3 = /.{0,1000}\.exe\sshadowcred\s\-c\s.{0,1000}\s\-f.{0,1000}/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string4 = /.{0,1000}\/S4UTomato\.git.{0,1000}/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string5 = /.{0,1000}881D4D67\-46DD\-4F40\-A813\-C9D3C8BE0965.{0,1000}/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string6 = /.{0,1000}Run\sthe\skrbscm\smethod\sfor\sSYSTEM\sshell.{0,1000}/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string7 = /.{0,1000}S4UTomato\s1\.0\.0\-beta.{0,1000}/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string8 = /.{0,1000}S4UTomato\.csproj.{0,1000}/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string9 = /.{0,1000}S4UTomato\.exe.{0,1000}/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string10 = /.{0,1000}S4UTomato\.sln.{0,1000}/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string11 = /.{0,1000}S4UTomato\-master.{0,1000}/ nocase ascii wide
        // Description: Escalate Service Account To LocalSystem via Kerberos
        // Reference: https://github.com/wh0amitz/S4UTomato
        $string12 = /.{0,1000}wh0amitz\/S4UTomato.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
