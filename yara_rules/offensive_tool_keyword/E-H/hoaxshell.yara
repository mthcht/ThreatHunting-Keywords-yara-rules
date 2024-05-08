rule hoaxshell
{
    meta:
        description = "Detection patterns for the tool 'hoaxshell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hoaxshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string1 = /\s\=\s\[H\,O\,A\,X\,S\,H\,E\,L\,L\]/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string2 = /\#\sAuthor\:\sPanagiotis\sChartas\s\(t3l3machus\)/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string3 = /\.\/hoaxshell/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string4 = /\.py.{0,1000}\s\-\-localtunnel\s/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string5 = /\.py.{0,1000}\s\-\-ngrok\s/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string6 = /\/hoaxshell\.git/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string7 = /\/http_payload\.ps1/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string8 = /\/https_payload\.ps1/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string9 = /\\hack\.ps1/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string10 = /169158f7ab05b90fd880b4921decbbe9ff0b13d04592b4711cdcb07216f2d02a/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string11 = /409faf186d5c7ab9c289f8942614c716baed7107b57003f96d76f717bc197df4/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string12 = /5721ff8bccba2fec3918c3464b519d9b02b69f0cc69639eaa8964174d4cc6e36/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string13 = /5ce31dbbcce69be63eaddd6759ea115162e96500f9ee185b106eb47c5c1417ce/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string14 = /6d96904c0085f49b27a47e4d75542fe8d28b6de9431038d72fdfdb2f51e43171/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string15 = /80a9715cb597950d540961b82e1f6793af205d9de2de5e61e6b6e53fc45845b4/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string16 = /8c484c384d66dd2821b9f1d4f963ae897fbf539b2ab495f3e93344635eb76f18/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string17 = /9915aa1e343c454c31a1011d51fa3f3410a54cc70256d232d2b7a00bd1bd5583/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string18 = /9a0da3eeb072abdcdce6774d9eb431a2be86b03c3a82e34c0cf464f8150c4e2e/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string19 = /bac188a072ffe2acbdd2d33035c3747b3febad807f5db13caa7b15bcb5bff415/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string20 = /def46f338013e516bbe3823ab661abb80e80e1388f2b57c3aa9dedee7f4735be/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string21 = /e277468009b97989146089c83231fa03247555b6cc2979b68d549a0d0e8ea0e1/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string22 = /Hoaxshell\.exe/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string23 = /hoaxshell\.py/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string24 = /hoaxshell\-listener\.py/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string25 = /https_payload_localtunnel\.ps1/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string26 = /https_payload_localtunnel_outfile\.ps1/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string27 = /https_payload_ngrok\.ps1/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string28 = /https_payload_ngrok_outfile\.ps1/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string29 = /https_payload_trusted\.ps1/ nocase ascii wide
        // Description: An unconventional Windows reverse shell. currently undetected by Microsoft Defender and various other AV solutions. solely based on http(s) traffic
        // Reference: https://github.com/t3l3machus/hoaxshell
        $string30 = /t3l3machus\/hoaxshell/ nocase ascii wide

    condition:
        any of them
}
