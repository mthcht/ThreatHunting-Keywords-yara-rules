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
        $string1 = /\sgmailC2\.exe/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string2 = /\/gmailC2\.exe/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string3 = /\/SharpGmailC2\.git/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string4 = /\\gmailC2\.exe/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string5 = /\\SharpGmailC2/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string6 = /946D24E4\-201B\-4D51\-AF9A\-3190266E0E1B/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string7 = /CE895D82\-85AA\-41D9\-935A\-9625312D87D0/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string8 = /GmailC2\.csproj/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string9 = /OrderFromC2\s\=\sReadEmail\(\)/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string10 = /reveng007\/SharpGmailC2/ nocase ascii wide
        // Description: Gmail will act as Server and implant will exfiltrate data via smtp and will read commands from C2 (Gmail) via imap protocol
        // Reference: https://github.com/reveng007/SharpGmailC2
        $string11 = /SharpGmailC2\-main/ nocase ascii wide

    condition:
        any of them
}
