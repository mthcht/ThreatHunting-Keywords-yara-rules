rule PILOT
{
    meta:
        description = "Detection patterns for the tool 'PILOT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PILOT"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string1 = /\#\sAuthor\:\sDahvid\sSchloss\sa\.k\.a\sAPT\sBig\sDaddy/ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string2 = /\/PILOT\/ATC\.py/ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string3 = /\/PILOT\/PILOT\.ps1/ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string4 = /\\PILOT\.ps1/ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string5 = /\\PILOT\\ATC\.py/ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string6 = /4870b4163315fa666dea8be03176d76aa215fe33187db45aca984e07b25ca827/ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string7 = /810950f1d775ffa916c75a85c79bb2a46f7c7250986be7748bfae90b04b33551/ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string8 = /Create\sa\sraw\ssocket\sto\slisten\sfor\sICMP\spackets\scause\sf\sscappy\swe\sdon\'t\sneed\sthat\sshit/ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string9 = /dahvid\.schloss\@echeloncyber\.com/ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string10 = /dahvidschloss\/PILOT/ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string11 = /Listening\sfor\sincoming\sICMP\spackets\.\.\./ nocase ascii wide
        // Description: Pilot is a simplified system designed for the stealthy transfer of files across networks using ICMP
        // Reference: https://github.com/dahvidschloss/PILOT
        $string12 = /run\-pilot\s\-targetIP\s/ nocase ascii wide

    condition:
        any of them
}
