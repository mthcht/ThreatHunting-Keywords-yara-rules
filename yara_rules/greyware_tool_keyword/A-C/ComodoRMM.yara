rule ComodoRMM
{
    meta:
        description = "Detection patterns for the tool 'ComodoRMM' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ComodoRMM"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string1 = /\.comodo\.com\/static\/frontend\/static\-pages\/enroll\-wizard\/token/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string2 = /\/RemoteControlSetup\.exe/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string3 = /\/tmp\/.{0,1000}\/enroll\.sh/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string4 = /\/tmp\/.{0,1000}\/itsm\.service/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string5 = /\/tmp\/.{0,1000}\/itsm\-linux/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string6 = /\\AppData\\Local\\Temp\\ITarian_Remote_Access_/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string7 = /\\AppData\\Local\\Temp\\Remote_Control_by_Itarian/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string8 = /\\ComodoRemoteControl\.exe/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string9 = /\\CurrentControlSet\\Services\\ItsmRsp/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string10 = /\\CurrentControlSet\\Services\\ITSMService/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string11 = /\\CurrentControlSet\\Services\\RmmService/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string12 = /\\ITarian\sRemote\sAccess\.lnk/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string13 = /\\itarian\\endpoint\smanager\\itsmagent\.exe/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string14 = /\\itarian\\endpoint\smanager\\itsmservice\.exe/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string15 = /\\itarian\\endpoint\smanager\\rhost\.exe/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string16 = /\\ITarian\\RemoteControl/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string17 = /\\ITarian_Remote_Access_.{0,1000}\.log/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string18 = /\\ITarianRemoteAccess\.exe/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string19 = /\\Program\sFiles\s\(x86\)\\ITarian\\Endpoint\sManager\\/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string20 = /\\Program\sFiles\s\(x86\)\\ITarian\\RemoteControl\\/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string21 = /\\Remote_Control_by_ITarian_.{0,1000}\.log/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string22 = /\\remotecontrol\\rcontrol\.exe/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string23 = /\\remotecontrol\\rviewer\.exe/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string24 = /\\RemoteControlbyITarian\s\(3\)\.exe/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string25 = /\\RemoteControlbyITarian_\(3\)\.exe/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string26 = /\\RemoteControlSetup\.exe/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string27 = /\\RmmService\.exe/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string28 = /\\SOFTWARE\\ITarian\\RemoteControl/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string29 = /\\SOFTWARE\\WOW6432Node\\ITarian\\ITSM\\/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string30 = /\>Remote\sControl\sby\sItarian\</ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string31 = /\>RmmService\</ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string32 = /cwn\-log\-collector\-production\-clone\..{0,1000}\.elasticbeanstalk\.com/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string33 = /ITarianRemoteAccessSetup\.exe/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string34 = /Linux\sITSM\sAgent\/.{0,1000}\s\-e\s\/tmp\/install\.sh\s/ nocase ascii wide
        // Description: Comodo offers IT Remote Management tools includes RMM Software - Remote Access - Service Desk - Patch Management and Network Assessment
        // Reference: https://one.comodo.com/
        $string35 = /mdmsupport\.comodo\.com/ nocase ascii wide

    condition:
        any of them
}
