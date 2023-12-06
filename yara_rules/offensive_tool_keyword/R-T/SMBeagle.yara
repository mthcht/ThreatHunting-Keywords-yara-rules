rule SMBeagle
{
    meta:
        description = "Detection patterns for the tool 'SMBeagle' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBeagle"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string1 = /\s\-\-dont\-enumerate\-acls\s/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string2 = /\s\-\-dont\-enumerate\-acls\s.{0,1000}\s\-e\s/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string3 = /\s\-\-scan\-local\-shares\s.{0,1000}\s\-e\s/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string4 = /\/SharpShares\/Enums/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string5 = /\/SMBeagle/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string6 = /\\WindowsShareFinder\.cs/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string7 = /SMBeagle\.exe/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string8 = /SMBeagle\.sln/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string9 = /smbeagle_.{0,1000}_linux_amd64\.zip/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string10 = /smbeagle_.{0,1000}_linux_arm64\.zip/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string11 = /smbeagle_.{0,1000}_win_x64\.zip/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string12 = /using\sSMBeagle/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string13 = /WindowsShareFinder\.cs/ nocase ascii wide

    condition:
        any of them
}
