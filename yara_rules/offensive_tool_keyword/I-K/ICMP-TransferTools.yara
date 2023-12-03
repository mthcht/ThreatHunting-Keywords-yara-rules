rule ICMP_TransferTools
{
    meta:
        description = "Detection patterns for the tool 'ICMP-TransferTools' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ICMP-TransferTools"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Transfer files to and from a Windows host via ICMP in restricted network environments.
        // Reference: https://github.com/icyguider/ICMP-TransferTools
        $string1 = /.{0,1000}ICMP\-ReceiveFile\.py.{0,1000}/ nocase ascii wide
        // Description: Transfer files to and from a Windows host via ICMP in restricted network environments.
        // Reference: https://github.com/icyguider/ICMP-TransferTools
        $string2 = /.{0,1000}ICMP\-SendFile\.py.{0,1000}/ nocase ascii wide
        // Description: Transfer files to and from a Windows host via ICMP in restricted network environments.
        // Reference: https://github.com/icyguider/ICMP-TransferTools
        $string3 = /.{0,1000}Invoke\-IcmpDownload.{0,1000}/ nocase ascii wide
        // Description: Transfer files to and from a Windows host via ICMP in restricted network environments.
        // Reference: https://github.com/icyguider/ICMP-TransferTools
        $string4 = /.{0,1000}Invoke\-IcmpDownload\.ps1.{0,1000}/ nocase ascii wide
        // Description: Transfer files to and from a Windows host via ICMP in restricted network environments.
        // Reference: https://github.com/icyguider/ICMP-TransferTools
        $string5 = /.{0,1000}Invoke\-IcmpUpload\.ps1.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
