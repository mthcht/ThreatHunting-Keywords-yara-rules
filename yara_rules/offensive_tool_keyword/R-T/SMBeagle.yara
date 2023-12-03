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
        $string1 = /.{0,1000}\s\-\-dont\-enumerate\-acls\s.{0,1000}/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string2 = /.{0,1000}\s\-\-dont\-enumerate\-acls\s.{0,1000}\s\-e\s.{0,1000}/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string3 = /.{0,1000}\s\-\-scan\-local\-shares\s.{0,1000}\s\-e\s.{0,1000}/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string4 = /.{0,1000}\/SharpShares\/Enums.{0,1000}/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string5 = /.{0,1000}\/SMBeagle.{0,1000}/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string6 = /.{0,1000}\\WindowsShareFinder\.cs.{0,1000}/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string7 = /.{0,1000}SMBeagle\.exe.{0,1000}/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string8 = /.{0,1000}SMBeagle\.sln.{0,1000}/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string9 = /.{0,1000}smbeagle_.{0,1000}_linux_amd64\.zip.{0,1000}/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string10 = /.{0,1000}smbeagle_.{0,1000}_linux_arm64\.zip.{0,1000}/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string11 = /.{0,1000}smbeagle_.{0,1000}_win_x64\.zip.{0,1000}/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string12 = /.{0,1000}using\sSMBeagle.{0,1000}/ nocase ascii wide
        // Description: SMBeagle is an (SMB) fileshare auditing tool that hunts out all files it can see in the network and reports if the file can be read and/or written. All these findings are streamed out to either a CSV file or an elasticsearch host.
        // Reference: https://github.com/punk-security/SMBeagle
        $string13 = /.{0,1000}WindowsShareFinder\.cs.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
