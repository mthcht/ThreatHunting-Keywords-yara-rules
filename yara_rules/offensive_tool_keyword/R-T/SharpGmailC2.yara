rule SharpGmailC2
{
    meta:
        description = "Detection patterns for the tool 'SharpGmailC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpGmailC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string1 = /.{0,1000}\sgmailC2\.exe.{0,1000}/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string2 = /.{0,1000}\/gmailC2\.exe.{0,1000}/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string3 = /.{0,1000}\/SharpGmailC2\.git.{0,1000}/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string4 = /.{0,1000}\\gmailC2\.exe.{0,1000}/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string5 = /.{0,1000}\\SharpGmailC2.{0,1000}/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string6 = /.{0,1000}946D24E4\-201B\-4D51\-AF9A\-3190266E0E1B.{0,1000}/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string7 = /.{0,1000}CE895D82\-85AA\-41D9\-935A\-9625312D87D0.{0,1000}/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string8 = /.{0,1000}GmailC2\.csproj.{0,1000}/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string9 = /.{0,1000}OrderFromC2\s\=\sReadEmail\(\).{0,1000}/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string10 = /.{0,1000}reveng007\/SharpGmailC2.{0,1000}/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string11 = /.{0,1000}SharpGmailC2\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
