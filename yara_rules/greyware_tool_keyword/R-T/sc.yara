rule sc
{
    meta:
        description = "Detection patterns for the tool 'sc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sc"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Get information about Windows Defender service
        // Reference: https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
        $string1 = /\s\/c\ssc\squery\sWinDefend/ nocase ascii wide
        // Description: script to dismantle complete windows defender protection and even bypass tamper protection  - Disable Windows-Defender Permanently.
        // Reference: https://github.com/swagkarna/Defeat-Defender-V1.2.0
        $string2 = /dnefedniw\s\seteled\scs/ nocase ascii wide
        // Description: start the RemoteRegistry service without Admin privileges
        // Reference: https://twitter.com/splinter_code/status/1715876413474025704
        $string3 = /echo\sstart\s\>\s\\\\\.\\pipe\\winreg/ nocase ascii wide
        // Description: create service with netcat
        // Reference: https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
        $string4 = /sc\screate\s.{0,1000}nc\.exe\s\-.{0,1000}cmd\.exe/ nocase ascii wide
        // Description: stop AV script
        // Reference: https://thedfirreport.com/wp-content/uploads/2023/12/19208-013.png
        $string5 = /sc\sdelete\sMBAMProtection/ nocase ascii wide
        // Description: stop AV script
        // Reference: https://thedfirreport.com/wp-content/uploads/2023/12/19208-013.png
        $string6 = /sc\sdelete\sMBAMService/ nocase ascii wide
        // Description: deleting the Volume Shadow Copy Service
        // Reference: N/A
        $string7 = /sc\sdelete\sVSS/ nocase ascii wide
        // Description: start the RemoteRegistry service without Admin privileges
        // Reference: https://twitter.com/splinter_code/status/1715876413474025704
        $string8 = /sc\sqtriggerinfo\sRemoteRegistry/ nocase ascii wide
        // Description: start the RemoteRegistry service without Admin privileges
        // Reference: https://twitter.com/splinter_code/status/1715876413474025704
        $string9 = /sc\sstart\sRemoteRegistry/ nocase ascii wide
        // Description: Stop EventLog service
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string10 = /sc\sstop\seventlog/ nocase ascii wide
        // Description: stop AV script
        // Reference: https://thedfirreport.com/wp-content/uploads/2023/12/19208-013.png
        $string11 = /sc\sstop\sMBAMProtection/ nocase ascii wide
        // Description: stop AV script
        // Reference: https://thedfirreport.com/wp-content/uploads/2023/12/19208-013.png
        $string12 = /sc\sstop\sMBAMService/ nocase ascii wide
        // Description: stop AV
        // Reference: N/A
        $string13 = /sc\sstop\sSophos\sFile\sScanner\sService/ nocase ascii wide
        // Description: stop AV
        // Reference: N/A
        $string14 = /sc\.exe\sstop\s.{0,1000}Sophos\sFile\sScanner\sService/ nocase ascii wide
        // Description: Stop Bits service
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string15 = /sc\.exe\sstop\sbits/ nocase ascii wide
        // Description: Stop EventLog service
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string16 = /sc\.exe\sstop\seventlog/ nocase ascii wide

    condition:
        any of them
}
