rule Pyramid
{
    meta:
        description = "Detection patterns for the tool 'Pyramid' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pyramid"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string1 = /\s\-generate\s\-server\s.{0,1000}\s\-setcradle\sbh\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string2 = /\s\-generate\s\-setcradle\spythonmemorymodule\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string3 = /\sLaZagne\.py\s/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string4 = /\spyramid\.py\s/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string5 = /\stunnel\-socks5\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string6 = /\.\\\\pipe\\\\mimikatz/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string7 = /\/_distutils_hack\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string8 = /\/DonPAPI\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string9 = /\/impacket\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string10 = /\/itsdangerous\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string11 = /\/LaZagne\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string12 = /\/lazagne\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string13 = /\/minidump\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string14 = /\/Pyramid\.git/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string15 = /\/pyramid\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string16 = /\/pythonmemorymodule\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string17 = /\/tunnel\-socks5\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string18 = /\@WanaDecryptor\@\.exe/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string19 = /\[\+\]\sAuto\-generating\sPyramid\sconfig\sfor\smodules\sand\sagents/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string20 = /\[\+\]\sMIND\sYOUR\sOPSEC\!\sServing\sPyramid\sfiles\sfrom\sfolder\s/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string21 = /\[\+\]\sprinting\sb64encoded\(zipped\(cradle\.py\)\)\sfor\sscriptless\sexecution\son\sterminal:/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string22 = /\[\+\]\sPyramid\sHTTP\sServer\slistening\son\sport\s/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string23 = /\\\\\.\\\\pipe\\\\blindspot\-/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string24 = /\\\\\.\\\\pipe\\\\keylogger/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string25 = /\\\\\.\\\\pipe\\\\netview/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string26 = /\\\\\.\\\\pipe\\\\portscan/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string27 = /\\bin\\uactoken\.x86\.o/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string28 = /\\bin\\uactoken2\.x64\.o/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string29 = /\\bin\\wmiexec\.x64\.o/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string30 = /\\DECRYPT\-FILES\.txt/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string31 = /\\Development\\GOLD\-BACKDOOR\\/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string32 = /\\impacket\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string33 = /\\itsdangerous\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string34 = /\\LaZagne\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string35 = /\\lazagne\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string36 = /\\netview\.x64\.dll/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string37 = /\\PIPEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string38 = /\\pxlib\\bin\\wmiexec\.x86\.o/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string39 = /\\pyramid\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string40 = /\\tunnel\-socks5\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string41 = /\\users\\public\\desktop\\Fix\-Your\-Files\.txt/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string42 = /8BF82BBE\-909C\-4777\-A2FC\-EA7C070FF43E/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string43 = /bin\\psexec_command\.x64\.o/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string44 = /hashdump\.x64\.dll/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string45 = /HOW_TO_DECYPHER_FILES\.txt/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string46 = /KeePassHax\.dll/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string47 = /keylogger\.dll/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string48 = /keylogger\.x64\.dll/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string49 = /ldapdomaindump\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string50 = /mimikatz\.log/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string51 = /minikerberos\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string52 = /naksyn\/Pyramid/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string53 = /pxlib\\bin\\kerberos\.x64\.o/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string54 = /pypykatz\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string55 = /Pyramid\-main\.zip/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string56 = /Release\-ReflectiveDLL\\Implant\.x64\.pdb/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string57 = /secretsdump\.py/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string58 = /Serve\sPyramid\sfiles\sover\sHTTP\/S\sand\sprovide\sbasic\sauthentication\./ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string59 = /timestomp\.x64\.o/ nocase ascii wide
        // Description: a tool to help operate in EDRs' blind spots
        // Reference: https://github.com/naksyn/Pyramid
        $string60 = /webinject64\.dll/ nocase ascii wide

    condition:
        any of them
}
