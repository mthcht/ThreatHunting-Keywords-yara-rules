rule Invoke_SocksProxy
{
    meta:
        description = "Detection patterns for the tool 'Invoke-SocksProxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-SocksProxy"
        rule_category = "signature_keyword"

    strings:
        // Description: Socks proxy -  and reverse socks server using powershell.
        // Reference: https://github.com/p3nt4/Invoke-SocksProxy
        $string1 = /Backdoor\:Win64\/PortStarter/ nocase ascii wide
        // Description: also known as PortStarter is a socks proxy and reverse socks server using powershell
        // Reference: https://github.com/roadwy/DefenderYara/blob/9bbdb7f9fd3513ce30aa69cd1d88830e3cf596ca/Backdoor/Win64/PortStarter/Backdoor_Win64_PortStarter_B.yar#L8
        $string2 = /Backdoor\:Win64\/PortStarter/ nocase ascii wide

    condition:
        any of them
}
