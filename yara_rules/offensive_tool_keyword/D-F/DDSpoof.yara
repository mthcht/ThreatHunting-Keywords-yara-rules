rule DDSpoof
{
    meta:
        description = "Detection patterns for the tool 'DDSpoof' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DDSpoof"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string1 = /\sddspoof\.py/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string2 = /\sdhcp_dns_update_utils\.py/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string3 = /\/DDSpoof\.git/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string4 = /\/ddspoof\.py/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string5 = /\\ddspoof\.py/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string6 = /\\DDSpoof\\networking\\/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string7 = /\\DDSpoof\\sniffers\\/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string8 = /\\sniffers\\sniffer\.py/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string9 = /\]\sDHCP\ssniffer\sidentified\spotential\sspoofing\starget\:/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string10 = /\]\sDHCP\sSniffer\sidentified\spreviously\ssniffed\sname\:\s/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string11 = /\]\sLLMNR\ssniffer\sidentified\spotential\sspoofing\starget\:/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string12 = /\]\sLLMNR\sSniffer\sidentified\spreviously\ssniffed\sname/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string13 = /akamai\/DDSpoof/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string14 = /ddspoof.{0,1000}\-\-enum\-name\-protection/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string15 = /ddspoof\.py\s\-/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string16 = /DDSpoof\\spoofer_config\.py/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string17 = /DDSpoof\-main/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string18 = /dhcp_sniffer\.py/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string19 = /from\snetworking\.dhcp_dns_update_utils/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string20 = /from\sspoofer_config\simport\sSpooferConfig/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string21 = /Invoke\-DHCPCheckup/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string22 = /llmnr_sniffer\.py/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string23 = /networking\\dhcp_dns_update_utils\.py/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string24 = /Path\sto\sa\sDDSpoof\sconfig\sfile\sto\sload\sconfiguration\sfrom/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string25 = /sniffers\.llmnr_sniffer/ nocase ascii wide
        // Description: DDSpoof is a tool that enables DHCP DNS Dynamic Update attacks against Microsoft DHCP servers in AD environments.
        // Reference: https://github.com/akamai/DDSpoof
        $string26 = /This\soption\swill\scause\sDDSpoof\sto\screate\sDNS\srecords\son\sthe\sserver/ nocase ascii wide

    condition:
        any of them
}
