rule xeox
{
    meta:
        description = "Detection patterns for the tool 'xeox' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xeox"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string1 = /\.xeox\.com/ nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string2 = /\\Temp\\XEOX/ nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string3 = /\\XEOX\\Agent\sWatchdog\son\sBoot/ nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string4 = /\\XEOX\\Agent\sWatchdog\son\sWakeup/ nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string5 = /\\XEOX\\Agent\sWatchdog/ nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string6 = /\\XEOX_cloud_agent_install\.bat/ nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string7 = /\\XEOXAgent\.exe/ nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string8 = /\\xeox\-agent_x64\\/ nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string9 = /agent01\.xeox\.com/ nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string10 = "echo Installing XEOX Agent" nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string11 = /https\:\/\/portal\.xeox\.com\// nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string12 = /ProgramFiles\(x86\)\\xeox\\/ nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string13 = /ProgramFiles\\xeox\\/ nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string14 = "ui/rest/download/xeoxagentgeneric/" nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string15 = "XEOX Agent for Windows" nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string16 = "XEOX Agent Service" nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string17 = /xeox\.com\/ui\/download\// nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string18 = /xeox_service_windows\.exe/ nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string19 = /xeox\-agent_.{0,1000}\.exe/ nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string20 = /xeox\-agent_x64\.exe/ nocase ascii wide
        // Description: Easily access and manage Windows devices remotely within XEOX - RMM abused by threat actors
        // Reference: https://xeox.com/remote-access/
        $string21 = /xeox\-agent_x86\.exe/ nocase ascii wide

    condition:
        any of them
}
