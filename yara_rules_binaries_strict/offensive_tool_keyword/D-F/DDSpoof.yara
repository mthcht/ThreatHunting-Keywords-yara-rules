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
        $string14 = /ddspoof.{0,100}\-\-enum\-name\-protection/ nocase ascii wide
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
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
