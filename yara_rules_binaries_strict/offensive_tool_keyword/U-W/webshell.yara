rule webshell
{
    meta:
        description = "Detection patterns for the tool 'webshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "webshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string1 = " - Antichat Shell" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string2 = " - c99madshell" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string3 = /\s\-\sFaTaL\sShell\sv1\.0/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string4 = " - KingDefacer" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string5 = " - Locus7Shell" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string6 = " - Storm7Shell" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string7 = /\s\/c\scopy\s.{0,100}\\windows\\system32\\config\\SAM/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string8 = /\sDo\-Exfiltration\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string9 = /\sevilscript\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string10 = /\s\-InputObject\s\$backdoorcode\s\-Append\s/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string11 = " passwords was bruted" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string12 = /\sPort\-Scan\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string13 = /\$backdoorcode/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string14 = /\$PowerpreterURL/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string15 = /\.\.\\\.\.\\\.\.\\\.\.\\\.\.\\\.\.\\\.\.\\windows\\system32\\cmd\.exe\s\/c\s/ nocase ascii wide
        // Description: A collection of webshell
        // Reference: https://github.com/Peaky-XD/webshell
        $string16 = /\.php\?cmd\=cat\+\/etc\/passwd/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string17 = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/apache\/conf\/httpd\.conf/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string18 = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/apache2\/conf\/httpd\.conf/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string19 = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/http\/conf\/httpd\.conf/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string20 = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/http\/httpd\.conf/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string21 = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/httpd\.conf/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string22 = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/httpd\/conf\/httpd\.conf/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string23 = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/httpd\/httpd\.conf/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string24 = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/usr\/apache\/conf\/httpd\.conf/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string25 = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/usr\/apache2\/conf\/httpd\.conf/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string26 = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/usr\/local\/etc\/apache2\/conf\/httpd\.conf/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string27 = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/usr\/local\/etc\/httpd\/conf\/httpd\.conf/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string28 = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/Volumes\/webBackup\/opt\/apache2\/conf\/httpd\.conf/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string29 = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/Volumes\/webBackup\/private\/etc\/httpd\/httpd\.conf\.default/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string30 = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/Volumes\/webBackup\/private\/etc\/httpd\/httpd\.conf/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string31 = /\/1n73ction\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string32 = /\/Ani\-Shell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string33 = /\/Antichat\sShell\sv1\.3\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string34 = /\/AntSword_.{0,100}\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string35 = /\/arabicspy\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string36 = /\/ASP\.NET\sWeb\sBackDoor\.aspx/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string37 = /\/ASPXspy2\.aspx/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string38 = /\/AspxSpy2014Final\.aspx/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string39 = /\/Backdoor\.PHP\.Agent\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string40 = /\/bat_b4tm4n\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string41 = /\/bypass\-iisuser\-p\.asp/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string42 = /\/bypass\-waf\.asp/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string43 = /\/bypass\-with\-base32\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string44 = /\/c99_locus7s\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string45 = /\/c99_PSych0\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string46 = /\/c99_w4cking\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string47 = /\/c99madshell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string48 = /\/c99shell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string49 = /\/CaiDao\-Webshell\-Password\-LandGrey\.jsp/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string50 = /\/create_webshell_with_py\.py/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string51 = /\/Cyber\sShell\s\(v\s1\.0\)\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string52 = /\/CyberSpy5\.Asp/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string53 = /\/d00r_py3\.py/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string54 = /\/darkfire\.bat/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string55 = /\/devilzShell\.asp/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string56 = /\/devilzShell\.cgi/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string57 = /\/devilzShell\.jsp/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string58 = /\/devilzShell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string59 = /\/Dive\sShell\s1\.0\s\-\sEmperor\sHacking\sTeam\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string60 = /\/Do\-Exfiltration\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string61 = /\/ELMALISEKER\sBackd00r\.asp/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string62 = /\/evi1m0\.bat/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string63 = /\/evilscript\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string64 = /\/exploit\/nc\.exe/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string65 = /\/fuck\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string66 = /\/g00nv13\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string67 = /\/Get\-WLAN\-Keys\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string68 = /\/Godzilla\.java/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string69 = /\/Godzilla\-BypassOpenRasp\.jar/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string70 = /\/h4ntu\sshell\s\[powered\sby\stsoi\]\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string71 = /\/itsecteam_shell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string72 = /\/ka0tic\.pl/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string73 = /\/KAdot\sUniversal\sShell\sv0\.1\.6\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string74 = /\/Liz0ziM\sPrivate\sSafe\sMode\sCommand\sExecuriton\sBypass\sExploit\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string75 = /\/Macker\'s\sPrivate\sPHPShell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string76 = /\/NetworkFileManagerPHP\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string77 = /\/NIX\sREMOTE\sWEB\-SHELL\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string78 = /\/Perl\sWeb\sShell\sby\sRST\-GHC\.pl/ nocase ascii wide
        // Description: A collection of webshell
        // Reference: https://github.com/Peaky-XD/webshell
        $string79 = /\/perl\-reverse\-shell\.pl/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string80 = /\/perlweb_shell\.pl/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string81 = /\/php_custom_spy_for_mysql\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string82 = /\/php_webshell\.py/ nocase ascii wide
        // Description: A collection of webshell
        // Reference: https://github.com/Peaky-XD/webshell
        $string83 = /\/php\-backdoor\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string84 = /\/php\-backdoor\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string85 = /\/phpkit\.py/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string86 = /\/phpkitcli\.py/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string87 = /\/PHPRemoteView\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string88 = /\/phpshell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string89 = /\/PHPSPY\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string90 = /\/Port\-Scan\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string91 = /\/Powerpreter\.psm1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string92 = /\/Prasadhak\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string93 = /\/r57shell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string94 = /\/r57shell127\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string95 = /\/remot\sshell\.pl/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string96 = /\/s72\sShell\sv1\.1\sCoding\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string97 = /\/SafetyKatz\.dll/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string98 = /\/scdc\/bob\.jsp\?f\=fuckjp\.jsp/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string99 = /\/Shell\/reflect\.jsp\?u\=http\:\/\// nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string100 = /\/shell\?cmd\=whoami/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string101 = /\/Shu1337\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string102 = /\/silic\swebshell\.jsp/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string103 = /\/SimAttacker\s\-\sVrsion\s1\.0\.0\s\-\spriv8\s4\sMy\sfriend\.php/ nocase ascii wide
        // Description: A collection of webshell
        // Reference: https://github.com/Peaky-XD/webshell
        $string104 = /\/simple\-backdoor\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string105 = /\/simple\-backdoor\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string106 = /\/SimShell\s1\.0\s\-\sSimorgh\sSecurity\sMGZ\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string107 = /\/SnIpEr_SA\sShell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string108 = /\/Sst\-Sheller\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string109 = /\/SweetPotato\.dll/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string110 = "/tmp/angel_bc "
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string111 = /\/Webshell_Generate\-1\.1\.jar/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string112 = /\/webshell\-123\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string113 = /\/webshell\-cnseay02\-1\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string114 = /\/webshell\-cnseay\-x\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string115 = /\/WebShellKillerTool\.zip/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string116 = /\/WinX\sShell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string117 = /\/Worse\sLinux\sShell\.php/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string118 = ":ddos-udp - started udp flood" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string119 = /\\1n73ction\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string120 = /\\Ani\-Shell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string121 = /\\Antichat\sShell\sv1\.3\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string122 = /\\AntSword_.{0,100}\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string123 = /\\arabicspy\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string124 = /\\ASP\.NET\sWeb\sBackDoor\.aspx/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string125 = /\\ASPXspy2\.aspx/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string126 = /\\AspxSpy2014Final\.aspx/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string127 = /\\Backdoor\.PHP\.Agent\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string128 = /\\bat_b4tm4n\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string129 = /\\bypass\-iisuser\-p\.asp/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string130 = /\\bypass\-waf\.asp/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string131 = /\\bypass\-with\-base32\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string132 = /\\c99_locus7s\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string133 = /\\c99_PSych0\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string134 = /\\c99_w4cking\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string135 = /\\c99madshell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string136 = /\\c99shell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string137 = /\\CaiDao\-Webshell\-Password\-LandGrey\.jsp/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string138 = /\\create_webshell_with_py\.py/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string139 = /\\Cyber\sShell\s\(v\s1\.0\)\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string140 = /\\CyberSpy5\.Asp/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string141 = /\\d00r_py3\.py/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string142 = /\\darkfire\.bat/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string143 = /\\devilzShell\.asp/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string144 = /\\devilzShell\.cgi/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string145 = /\\devilzShell\.jsp/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string146 = /\\devilzShell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string147 = /\\Dive\sShell\s1\.0\s\-\sEmperor\sHacking\sTeam\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string148 = /\\Do\-Exfiltration\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string149 = /\\ELMALISEKER\sBackd00r\.asp/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string150 = /\\evi1m0\.bat/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string151 = /\\evilscript\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string152 = /\\fuck\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string153 = /\\g00nv13\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string154 = /\\Get\-WLAN\-Keys\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string155 = /\\Godzilla\.java/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string156 = /\\Godzilla\-BypassOpenRasp\.jar/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string157 = /\\h4ntu\sshell\s\[powered\sby\stsoi\]\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string158 = /\\itsecteam_shell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string159 = /\\ka0tic\.pl/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string160 = /\\KAdot\sUniversal\sShell\sv0\.1\.6\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string161 = /\\Liz0ziM\sPrivate\sSafe\sMode\sCommand\sExecuriton\sBypass\sExploit\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string162 = /\\Macker\'s\sPrivate\sPHPShell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string163 = /\\NetworkFileManagerPHP\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string164 = /\\NIX\sREMOTE\sWEB\-SHELL\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string165 = /\\Perl\sWeb\sShell\sby\sRST\-GHC\.pl/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string166 = /\\perlweb_shell\.pl/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string167 = /\\php_custom_spy_for_mysql\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string168 = /\\php_webshell\.py/ nocase ascii wide
        // Description: A collection of webshell
        // Reference: https://github.com/Peaky-XD/webshell
        $string169 = /\\php\-backdoor\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string170 = /\\php\-backdoor\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string171 = /\\phpkit\.py/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string172 = /\\phpkitcli\.py/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string173 = /\\PHPRemoteView\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string174 = /\\phpshell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string175 = /\\PHPSPY\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string176 = /\\Port\-Scan\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string177 = /\\Powerpreter\.psm1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string178 = /\\Prasadhak\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string179 = /\\r57shell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string180 = /\\r57shell127\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string181 = /\\remot\sshell\.pl/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string182 = /\\s72\sShell\sv1\.1\sCoding\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string183 = /\\SafetyKatz\.dll/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string184 = /\\Shu1337\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string185 = /\\silic\swebshell\.jsp/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string186 = /\\SimAttacker\s\-\sVrsion\s1\.0\.0\s\-\spriv8\s4\sMy\sfriend\.php/ nocase ascii wide
        // Description: A collection of webshell
        // Reference: https://github.com/Peaky-XD/webshell
        $string187 = /\\simple\-backdoor\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string188 = /\\simple\-backdoor\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string189 = /\\SimShell\s1\.0\s\-\sSimorgh\sSecurity\sMGZ\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string190 = /\\SnIpEr_SA\sShell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string191 = /\\Sst\-Sheller\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string192 = /\\SweetPotato\.dll/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string193 = /\\TexttoExe\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string194 = /\\Webshell_Generate\-1\.1\.jar/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string195 = /\\webshell\-123\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string196 = /\\webshell\-cnseay02\-1\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string197 = /\\webshell\-cnseay\-x\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string198 = /\\WebShellKillerTool\.zip/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string199 = /\\WinX\sShell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string200 = /\\Worse\sLinux\sShell\.php/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string201 = "<h1>JSP Backdoor Reverse Shell" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string202 = /\<h1\>Password\sHasher\sfor\sPHP\sShell\s2\.1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string203 = /\<h1\>PHP\sShell\s\<\?php\secho\soffender\s\?\>/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string204 = /\<h1\>PhpShell\s2\.0/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string205 = "<h1>Spider DDOS Shell" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string206 = /\<h3\>RFI\sOlarak\sKullanilmaz\s\.PHP\sOlarak\sHost\'a\sYukleyiniz/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string207 = "0031268c9cdcadd2f9c9c0b7655ba40ebbca9f506cea829cb0ad0a96cc51022d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string208 = "0044dbbe7f768c5b5464cca3fc0ace9850b2b41b628cb469a8173578f1d6335f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string209 = "005dff69ec258cc35c2a45f0103570c28895b910e4f987af28daa7c5b7c22926" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string210 = "009cd370780fdcd4471165da2278c8bb65d4837457a253d4d4bd42e9d88e3e9f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string211 = "00ae099c6c9284ab4cccd689e66872e5683c2665e3f73936d6e1f98cf248c775" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string212 = "0151aacf718ab65be46770339559ebaffa2cade02a77202d0cef37100856c95a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string213 = "01b0e8b416acdd571719f15ae31beaa7ca2f363c3d674f4ba03261fd3d33fb3d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string214 = "0202f72b3e8b62e5ebc99164c7d4eb8ec5be6a7527286e9059184aa8321e0092" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string215 = "02c66658356f846b14ef575627bb2ebbd65b0da6bb092470f95ea59362ee8c14" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string216 = "02ee841b1c0ff20dd6b50afd104fad2103b1736872173a1b2b036071f8219db1" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string217 = "030d68dfcc676b9d13c5cc954bf576d0ab617c972c93b21b838637548d697b79" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string218 = "0320ac39c0f62ed4b850c09e6cad3c7af53ed5ffbf48b1421ca6d4510c9a35ae" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string219 = "033c90882b07aaa708b6ab9f04202ed0d01a0599419538862ae2b5653e689316" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string220 = "0354365922cdfd77a8ef7f7fc3b1f757b7ba4a94cc2561875b766f178003f5c1" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string221 = "03bb58bdb5217b17e37c7c800aeb9505edd2e0f3e2a540a550ae4fccc49b5745" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string222 = "03dbbf1efbb0bd609da3b7daeda499231a229e11be374a46b9cc7e0d97f3ce64" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string223 = "045fca6b1696d9b40dc71999c384458f32e4c7164c8d91370020694547b60e15" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string224 = "04d10aaec0489662bc61d17ed9d1e5b7a89a74faeedb428d1f80395feafef4c9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string225 = "051597cb4fc84251a039fe931235dc5e418a20a290e90f91fa4ffc974108bb0e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string226 = "053e66e29158b7d72fcce76e452dff8b1b5cbeb90f40ddca171a1ddf88c14fef" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string227 = "05f91a311b1c92776945a93cc3d8774f586d9d217f0f5e11ac54c351a50e7dc3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string228 = "06c66818ff2074772a93f1f6f40047ddfcb60928b03b89cc6d132db0450c9f62" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string229 = "071665786d0527bd94736db21ce49db2a113e1429d0413dbbdde0975506394e8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string230 = "0750514b25767d24d1a2923f95d3b88b5018b7b44476828f7c36a1d4003bddf0" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string231 = "076ecfd382b059466f47da6ec57866373451cb46b5fa1921874c23f094aa8912" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string232 = "07d01f86a1a030d45d8fb8b372cfd986b8f3a7d530046f16acc5e82082e53ec6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string233 = "08422736c3ebf5b528cc404a39a20c8975d49758854115ee979ebff49282f5d9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string234 = "08a34b6f8df04ceec420e252fc484ac46a7f384a0c470e7abe4f1dc89762f067" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string235 = "08bb37b35346a2fc5bcc4c56ed101a95072de5bf7b5af36273d1277807c43a3e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string236 = "090600985a1db310b138b87ad8eb42f1db810379974a790a30c9cc8d55e81c17" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string237 = "0950b4561ed9e9dce2ce89ee2cd3e4c740700c399c6b8006afb1c9419569a1a7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string238 = "0a070709fc2cac96d80f18a03eb7c539958c51e392475a0789aef50181707613" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string239 = "0aed5355351bc856a6a92d226188bb66a13a8324792fb112f39401e080180e81" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string240 = "0b588d69dcb8efba81185ac65ec8a9ac051aaf3309523a01d2d360d2d283a0a7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string241 = "0bc53792d88e1638eb0772b7b3bad8cf04d4bb68d958fea9ddac7df9a8d09b77" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string242 = "0be065c34cebd132ea23ef20d51f13c21ad31428db2342bcddc0b4e182625e5e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string243 = "0c38fc9f070a1db92c2007447a97b7777565ca630097ca73a1b3c9f649d7183e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string244 = "0c5f8a2ed62d10986a2dd39f52886c0900a18c03d6d279207b8de8e2ed14adf6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string245 = "0c61a84a8b1d0ec97638505b72cd333f82840ffbe7f39c5ffae8efb31e45d0f1" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string246 = "0c94f85cb61c62e3f2124ea95d74c5fbd2901751d3536c23b36631ba800d628d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string247 = "0da34db46173eeb7c06ceb9732d5006a6463c802c5ac9bf2b0e40084b207f760" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string248 = "0dcb4aca167ac5f020dc3b55e8db707560a592152131fd78484392172107b688" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string249 = "0dcbd6cce79f768d9e9b79bc8c86be279779120b8232e32c1f3198ee56653518" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string250 = "0ee4ed7184673d6fc1163f85c3da8a78f5aa1464eda290697a903c5adb7b0006" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string251 = "0f1e0f2ea2fd99d208b3bfafe79363c0b905303e12456c5473cd229882cf8fce" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string252 = "0f556749b43ff623079348b6ad75ddbc03d011cf9d6b2e9d548f030259a1aef1" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string253 = "0f6cb2770be3533a4ab6b50f7d045c3c33cd2f61c37de652b638eef1217e3c41" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string254 = "0fd206b046e9a2b542a7a82d4aba38eba6339f813b60c4af451e48aa50bbc78c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string255 = "10b405045647c01fa0cd316da07236cf1ee0c60675b7ab515734995efe28adcc" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string256 = "10f310ef3189c07c1581a727a6edcd86c9b650f68c2a933cf7af272bf3acf9e5" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string257 = "11802597962f345ac2b1c9cd161eee89862b153a06ec00c90b84889f5d094379" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string258 = "11a5d052cdb215ea23fad710c786f4b71f7a5c76f18d76d8fc97750ea4eaa403" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string259 = /127\.0\.0\.1\/KingDefacer/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string260 = /127\.0\.0\.1\/r57shell/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string261 = "1270518f941a14c009fc80622178f1713c7bacb88ee0396e0d858454f04cff63" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string262 = "1286a0815c6982fadf3a1da2565fedfd133b8d07a5de1d592a640c3abbc2ffa5" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string263 = "12962d7fe733b60acfffc35698b22328453c2a04665c90758f53f31fdf81cbf8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string264 = "13b6173c509e41d78eff3266071dc52d6e45f81451d4203f20a761a748ce16f6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string265 = "13c6d7d3ec0c0713c9640cf99fccfe1f6ac615cc4d7b7edc4b0f6e574ab1c2a4" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string266 = "140bfb676a49c80b80f126ce16f37731aeb8ddbab4fdf67083676fc0d80c26e0" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string267 = "14ba976d3427c5982fb1348b6d9212646e63e7531311fb362496f801f312594c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string268 = "14d65cb6ca5442b1c30f51ea73199b7bf32db17f5bb6c483346c13e0014545b0" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string269 = "1594d2cb2fc051ab4dd77d0f6ec318f25f1430af50fdef934e3e996fbb91d42f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string270 = "15cb2dd2018c7d8d79752c3165c95ee8e42d70aac398d11dc41e236cbf997595" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string271 = "166bc58e721deee406eb5b85e40e6201745d6a7379d862d8a202485ab7295dd5" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string272 = "16b6ec4b80f404f4616e44d8c21978dcdad9f52c84d23ba27660ee8e00984ff2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string273 = "16e1e886576d0c70af0f96e3ccedfd2e72b8b7640f817c08a82b95ff5d4b1218" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string274 = "16fe7dadefa2d2331f40b56595f695a5d4852c2bba909fd099d4cb4d3bcbd90b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string275 = "183c3aa2fd81b6e9b3af4f376d96f57ab6557009d8abe5c6f849f4bb2a0111a9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string276 = "18da2934d552b548d067b86dc22cad36399bb3e24395de0f9c13b4f6a8f09b74" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string277 = "18fce84919acb963f9ed765c122a5ff844a62036b4bdfaf6c95a30907d14460f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string278 = "195c384a1caf0e50ea74c69de39b90e27dcc9635d951f8a652cc322696614e59" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string279 = "19f0c96e4b201d75902e2eb10fdeb4aba4fe00f7f5bc897097c1f3f8262fca47" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string280 = "1a51e5f891a81351f0e0bdc2bca6c2d4aaa0bc07e0a313b2cec8e77a63d236a1" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string281 = "1aa328de71a7199a03005b39e9c8e73c2ca6f73e9d55615189cf21690f7cd6f9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string282 = "1aab058ee1e02a5d2b3cf8604b9bbeaa6dc2cf4a383cf43916a19169ec875a9c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string283 = "1c0a207ce57e860adae1f3c0d7a0cd5c1312467950ada3216ea22b4dca5d42bb" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string284 = "1c433a8035d4dba34f796841bdd25045167a59c41c716548b00a7439146a48a5" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string285 = "1c7e49aa70c93b8d84d80679b4b869c58c84e7bacef8dee13aff9837423d8f4d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string286 = "1d49fd236c80d04b58e6b18b516392332dc80171a56d03104be873eb9978e889" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string287 = "1d6ccca21efe8d8de4cc4aa1598fc4d9ed15e82f66c84f927b411f255e0faa8c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string288 = "1d72c6c584e8d98f42b7ed368a592e7d24bd773f611f174fa9834c0d949a46fb" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string289 = "1df43548fa3f18b13fef3d1d1e7c5349ec9de9446e391b9dbb09d1bd57cc9be3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string290 = "1e078b5c876c4e5070b19a314be3b7385a3e2fc6a427f2ffcc2a2340b7c2b52f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string291 = "1e895d59aad4217f8c65ac581d28233b0f4415629d28a37aebf0743d07174848" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string292 = "1ed3cce97e2fead6c5f784b3df60d104db026c106a049e9b9a613e7407822c1a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string293 = "1ef59c9201490b379ef17e7bb62adb414e2920e3daae6e866f230567fb0c5866" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string294 = "1f39ce08fe915d5a346405fcacf6287c772c7c3fcb609bc34d32a5c90afe8050" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string295 = "1f3a6d3687d57689a7ba7ff64c30fa268fa1e6fffc0021c3c01a2e0b11a069ec" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string296 = "1f4a265fc64ca0cee0bf95e15d039a1a8c587cd1fb7b41de536226a679bed4a3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string297 = "2018bdc2964ffdea2e1e42f9bc8f5480b6203dac3bafc7eee958fb4d90d59139" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string298 = "20763b3e829f0226ebb2b7e192d8728f2e61a81bf5ee9d59da4c80a078ec087f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string299 = "20ceacaac5215e9a2e5bb82861f1391382fc7cb132c9c57f706b216f5f975b0d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string300 = "20e9054570f81d5aa05864a0bcc292274f2bc48fb593ba26978ede76663c2b6f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string301 = "21c1f56c071851f53f1b27dfe85fed9bd7da3141a9d80f665be59d370f761b34" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string302 = "21c56f056bbf9526c9e4b73407ddac030dd9379bc4fa2813ac28662446567faf" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string303 = "21fc92b2d8e6c439a04cb584d0b33c49e6c9460d754429795f3c7de68777772c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string304 = "2209de0546bd10397e30fa70f9c04a6730bdeddd610ef7fbee491ed86a881c95" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string305 = "221ca3050fc71ed69e11ba092468ca4a99220e3dbb23e5c7d37b3f15a77b02e7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string306 = "22348216348f97cfb574f25a1528cf1a766ccb1e70d33961a6f1b6cf4feff23c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string307 = "22c276ff5b6b7158990cbeddea6368894e0b4477c11ea714b8b30401096f92df" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string308 = "22f7e0f4c88ff065df8e983b5cd2bb1cb7e218e7eddbf34a950711cff3657dc9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string309 = "22f7fe7f3c58f04ba3e26f3b779dd14bfed6aff19d4d9e6fa290ae2ce0d71f51" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string310 = "2309aee5d6244b80e7b1f98d62c87d68e97e0acaf233688af07b6a8439f85b7d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string311 = "23169d2107567f31b9cde9d04b8a9aeee99c34dc3261c81fd7a897a603ec4606" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string312 = "23fcda1ac1f7e1d1644077f5e28759c56a93216e95b6a82e84654b6bfeb0acfd" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string313 = "2481d8ac474510659f30763ac99dd577b78285594f0ba281f08d83829ec56225" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string314 = "24ae403a4b2844b646f6520b7eb7c6817f739759afca42b66c250424c46bc89a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string315 = "24f608e725ca4ca008b780bde8be2d27bfd9a1b4c9b4a106d4f679e75a21d2f2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string316 = "250abcb0da278460620cef30b9ab1c401b0e57a53642e5f6b357b9ca6b4fbfdc" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string317 = "25151ae98c5657bd40a5318e86c8b341bf7a59d7e04b6b4658e644e6e6c42687" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string318 = "257cfcdd6311f8c05091d2215e6d0be3bc628f2f34b69668aed74a331fc099c5" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string319 = "25810493e3a4bd9076cdcdd14f7c7a6e6c159098ab393dd10375690a37bd0125" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string320 = "25dd4db0e48fdc0552e9be4c65e9ae2af7c25e0e63ce4dc08f3f6083d7d971bf" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string321 = "2626b0227e8a7c5451bbc27b3988db5214b47f004c5856d4fdadd31731010d2e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string322 = "26654c4213cbaff5769618c96be371610ea48ff3f85e909786b9218063e95214" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string323 = "266b50dd481bfa762dde5f54c014cdfa3b6bb6d3d1e05a7a0c49a4fb81eceb3c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string324 = "266e26430006ea2f97fb62e9f9a070a64af7af9a4879a8f8ca3008c5434d3ce5" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string325 = "26d349e65525178dd3b6d69332c479362ce9be10e6c311b178e07bc82c904d16" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string326 = "27384243d50bfa14910b2a3993a1b42b8e44ce75bf94f3d17b1ee02a7ce66144" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string327 = "2747fb657f7469ba916c90e46cf298bcb89d1fc92d8aa8956081db0e631c779b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string328 = "2764294962b243eb9359e8678fd76af9b2dc2d061a78942b717eccc5f1a1aaad" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string329 = "282dd8c14f421dae167e02a50da13d210e34059230779eb30b70e222b04e55c6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string330 = "2952a3dbebc375e94bafc4a6fcfa3ccfa8993525779bb29b26684e21bcebd7c3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string331 = "2a3543146a8e544c425b5ffcb70dc00e0475e0c4de5bf8aae379ee04cf4d322a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string332 = "2a83ad9a1a2be9e1d7e3ddda77b758d6914fa72d94d75924e4579867a1cfeaf4" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string333 = "2a95a39ae2f86f2479690a7b54ad9038be74c8b95e4a978f4975f7c8f0d028d9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string334 = "2ab55fdad5aa04a7a7a68b1284869347a1589891476cb03089c9106cff8e2d38" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string335 = "2b28e9992fa85d77397f442efeb893814d68c6d97a525ebe8d900e6bda043ac4" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string336 = "2b5e05019d56c493715bbc485747a383bfb6dd8c2d44aa0f54fdbcf9cec78d4a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string337 = "2b94da663635e7a44ea485c80f1b6ade7a05a6f8a927c80568c2570b98ed29e2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string338 = "2c0a115ffe1cb4d1672aa77035349763e0c2814bb9ffce04ee368c1b7874ac89" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string339 = "2c49f9006a48adaa0445950dcf5fe02141c0891c5fd23bec5e9f9fcd8ef8f291" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string340 = "2c511a9099fe0f45494a74446a1938f755a5f783c6ed40def55c2fe99543a571" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string341 = "2d07b219eaa35bbe5dafe4b618f53b293d69779ed3596432a41c12ec14bc0b42" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string342 = "2d24b7562b9165724b631386fc3e2af255e42bddedb3b05a297cb2251ad64e0d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string343 = "2d64cabcf01bbdb919864475061ca0b5b14429faa6c1da87d575bfa0d56a9329" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string344 = "2d6fa1c8a808ef5f183950224a90249f798804b6634a6145f9506446076d39ea" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string345 = "2e09c605521fc3d2a8cdda835b54a6054a577071f5ea3f26add10cbfe0dcb369" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string346 = "2e47db0e24601fb84751b429e0bc672a644961168901759e6e96a97896bb6f99" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string347 = "2ee0ee369247cdd09022301ea9967eb2e6fe70526499c7968a980ef46f2d0645" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string348 = "2f00562c23c765a32f3e1b39da4aae0db8cf0d47e19c800bba2678c7be198503" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string349 = "2f511fc2e09cb09ff9711958973b513316e75827c85d1b787c7f8befc580c0f3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string350 = "2f64baa9a60ff7e4114c278a8538dc6807c52b5aed17a158cd6e4bbc89df93e3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string351 = "2f77333c8b958d992eb2bbbdca80efd3a90f95a45c1b9738d16ee8e0a0f3c3f8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string352 = "2fea83d7bfccf5b1e8a5047b27d872bcfb18f5aa4ab71e038c4f56554ee2f108" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string353 = "30939d4bfbff459b8de9419897dbd48b10032790935f175c39796cbb605651fd" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string354 = "30c5d870db5787b40d4ccd8e311a03805aed56149d5f183f0d29c51643053782" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string355 = "30e59e027270c23d6ffe6b89e2f149d5da63533e07e8f365fee9704dd722f002" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string356 = "3140428b83a45c63384cb4929316ac23dd8ca006a7b8ce4efd97f88f45e85d9b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string357 = "3141b56aedfc8fafa19b406b904264a35451008ce5cdc4cff6255f25ea77591c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string358 = "315edea7f4235f5a8c3ca70bacb414e4694e963f41df5c367aa7a0448581ff56" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string359 = "3177334ae8eb2317c5e0775b05a002a43360a76dea4d068d35f9c271c1499408" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string360 = "319040bad23d4d4c36c6db35f2d44650aba8ef3e34652f3a39bb383cf6f988db" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string361 = "31ba44f9696e84b64506a11c691d123f3298d7de9c9be6ed786cb1258518a45a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string362 = "31ea6e085e202e97d79ce006e683f3bdb29e557899a52f6f284e40b86d434fb6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string363 = "32dca4493f6efae39b557be6803c241f7d88f7871f0fb5fde9c4ea0175d77518" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string364 = "330ffb5abd7f035bc263a5f5938325aeb91a4d22e15ed1814d6a78098e00fb36" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string365 = "3338c8a4e14d314a4a3313dc67cb1e1f2274c8b30cc2cdf55586d7cdba2a6d68" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string366 = "33513a09abcccf0f96dec767ad33fd00b6086d00232be225457ab9bec12bd45b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string367 = "3365bdc76c116ce83c56e7d2e4c7c046a6a82d24bb23982c46bdb6476c6807f6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string368 = "337dcd762be6b0cd6566fd44bc161387d836557f78cc595804a2a04623a5f505" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string369 = "339946aaf56d168682d5823ec417bfe5d5d7e9879b85a1d4672c75aab8a77c0e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string370 = "33f8a337f8226b5c4dc3ef7ded1d82973b81f9b188123e1db551c7265831b141" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string371 = "3443273660bae2e0f9feaaece977a654529e7161a2b753fddf986b0bbab1dca9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string372 = "34ea6934d6d4eca71440e0d0f3f31fb8714d2a558d1b33394ee0ba5b8b58589f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string373 = "35c8e39ebbd238ce994c3bb0cb274e37f2b5e94af2488e6009ecc872d465340b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string374 = "3629589a44e2c3b8d1bbc7ae8c779b0a7522755906e09d4bd14b76d6e168741c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string375 = "36306a3cbeee8bd6405ac58a4800eec4adf403c3c3fb3d70bd7c73e8df17675f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string376 = "36663e4535c25c63a9debb293737016321c3dec8425eca3fff69ba37a7603d63" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string377 = "36e459305e1df9cc100dff6ecfc2ef7fd1ef63ad6e989c8c9802533b0f78b9e4" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string378 = "37029ec9cdb5036dfc1635ce9e69c358f39271bd6300a170e2b61d1d4ac3e526" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string379 = "37203cc51ff33325e533e58de57884ecb9f28bea3b3e5fda2f0c98d1ce6d61e4" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string380 = "37d1dfeec72edc0814efec084b8794847d250291eaadf0fbc9b9e2c5602b32ab" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string381 = "382dbe7341c3b3970dacf304a4de5a6df18fa39cf13d4ca3e4441aa912e100f8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string382 = "3911d52883ec32df91fde022f08e4acf0ee9d4d52990b36cb603da6bde167f32" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string383 = "3977d160d5b65edf6e6cf957b4903df9d69cd060ae9c7e1142edd307958c18b7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string384 = "39b0071c3a25122df7a0e7cc29cd450b2a8a3caded094f3ab678eba80014c33c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string385 = "39feb7b45b04c809b59430596ccf37468132d8f19e70b38dec1cc596268079d3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string386 = "3a3dabe266b3a40a834c57793083a5915c526b1bb2cf7939737aab035bc7ffeb" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string387 = "3a5dbd02b77211a50f970d07e5f7cb993788770bb9ea8e9c2af3041aefbb25b5" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string388 = "3a8f9dbdb5a70ab427c99799ea3782cb768576d1affd329293f994f665bc2dc8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string389 = "3aefe6d2e264cb53be7ea8609f4d80d6264d98d051b446821e6efff94ce2baa6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string390 = "3b5369544fbeb32a7685da8992f08261e7ce6b12159b3920618c29a7af930f0a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string391 = "3ba5a2d4b11f562ab3da3fc87c2889a16523833ba4ede090ffed40a20e643ed9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string392 = "3bd5e92bb40161c47fc8610c85646cb66b3de7e121e4fd03789772441a06c858" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string393 = "3c02853e5ddae494fd654fc0b44687f5c45a03092f6a2594725b8589928e645e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string394 = "3c4f49964a9cdf416005fa4a4cd54b5130cca78b0b810e5122ad0870f474fb49" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string395 = "3c59dc54401bcc15c44acc94ce543f7f3e40b164a12815892487aa137b1f4fc7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string396 = "3daa15880b0da9e659c2f8df0beb56c5a7637e8a96cfe1a4b171358b4370b4f0" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string397 = "3e5eb4425abfdce29a04e04cea468e032ad8c0af5a904681f05d9f2e5a4d31a5" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string398 = "3e7c6abf54cf667239605c72fc13e5ae4be53e65ca83887510362a33a7115a0d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string399 = "3e86bf634c4f10502b64f39dba0990e9357ff141d61020b76dd2f3514f02910e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string400 = "3ea13e5df7db6342688575fe5bbc234291a6402d56f96d9b26e2b63240505cef" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string401 = "3f3a5c2cf1feee383a348a89709d74af305d4c5dfd3d88150ec1189fadc76877" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string402 = "3f6ee397df853f26f467795a8112996db83b6db7f832c332964c954ee4cf7cd8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string403 = "3f890ba7237462ed2d3fdfc82d5c6b67ae06fdc134d3a174a2e0b1c7b931204e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string404 = "3f8db76e847878adee99ebbd0bb4399d65839f8eeb47506df23a1e10f2bd63b4" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string405 = "3f97c1116190ffd5984c92985bd12e0c92a044ca760cbb110ba9fe65a2703de4" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string406 = "404b35cd0c4124111995599f346050da72845a04fe5dacd53d8088692e4a3816" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string407 = "40c48046580b66d7651f993380e92cf3e0931261134626e52e7be96132341e00" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string408 = "41200aacf9f458f0c7dc10d200937ef343a8625d249557f4132605ccb6dc0fc5" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string409 = "419852f196eaa5b3d51faafd60fa1fee9a6ac5392da93d99e52b8abf2a5552c1" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string410 = "41ee1cd6256819570f05de5815f4cfe6dab88e30cf25ccd5f52bcb948e16e70c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string411 = "420809c2672f7197f17c6aa6cd1530d6b703f76a413a6de4e0d1538fdd2cceeb" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string412 = "425fe29b9c497a1ea8c67cd9fe06cdf257efdeb73a2ebcd091039a2ff92434cd" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string413 = "42bb8ff889457f6d971aaaff1ccb6550c66bfab0af20c534664a03346a3a777b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string414 = "42dd027e9404976db7b50f3ba2885c133d1516f3cb03b2f1a715a26de79ad330" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string415 = "43d446b0423388d156a4d8c61a65ab5e1492b045fbfcd528689d525af758678d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string416 = "441c29048f8aee256eee59a66098ff2223b1f225386aa9d91b8d391ea0f59cb2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string417 = "447286de6b80a554a59b971a84aed07594bb2bfb66e0760363a6b36b930c35ce" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string418 = "44b33b5a598a9ad02356ba66221a7270a97ea4ad6f653b64a030e35fabf63e49" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string419 = "45570458c8065fd92b833dbf89ed9777f7326a6802cb0b25b7b499e486411e52" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string420 = "455944be49563e9e917624046e1d638743d7579238f28456fff1ea9b7c21ae28" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string421 = "4593dbaecd6d4e05d7aa7e2cb8cc8ce4b9d1ccc1a6b26e40fdf72fd8a80e7d07" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string422 = "463183549b3e427b66613231ef130febb24b0c555747528075e1168fc627765f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string423 = "4695acbd22ff9cce0fa585459cbaaf879ffdd59f0f6f583074902c34773e6293" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string424 = "471ff2b50c255470e1ed51c9e712abfb95d36803c1c1e186f9048e5118a1a62b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string425 = "47754449ae1a74f008d1a322a1b66110af723cf08bc9b866723f58473d02e444" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string426 = "48a5568360a31333aa809cc28c5a5669a028d32a6ea4b1037813745c5ceffbcc" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string427 = "48fa7261a91c16d1d37f13b483677729ee83cac7c90633cad4e1142eb41aa1d0" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string428 = "49c0747721f7e7e5d776d23d83f705951595de8e63df7b7afb43824f4a3415f3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string429 = "49cf75f28e0c89a8fac346f1c794ff1bcc985c85f47f17e1ce77de5216eab525" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string430 = "4a559425f55fd91596a8ad4c4caba2c2078900678b61b5097aca0b4b12cac605" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string431 = "4a84c293927779fba03f1947803557c22ba6ad4b10dcc9780827df5cdeafa2ed" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string432 = "4abe9875f67c1fe6a007397189962a3d3b99a6251c601128936dfbd6709c193d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string433 = "4acaf168b97204a65d3bb68658755a143837689a38bfa0d7705eee432e4cdcc4" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string434 = "4b999cd6a88ade1b7cd18b87d34495d4a03af9202a4f8b6a20b98f144c01d084" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string435 = "4c146c6027d7714c632de29b05610a352ece4a5a9bae1d629d199ce9cf977d73" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string436 = "4c205dad7c4b9f5f35fc8f127bc216e691f6f323e7b976512cecdce4f97a1bee" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string437 = "4c4497c8203934c12bd09ac33096b11ced541744f6b4121c2967e4cfea6e250b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string438 = "4c54cdeb6cd364faeacd795930d6878dc04f38dd2e1fd4c7b850967085d9ab01" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string439 = "4c739d4f3575d5cb19d15fcc02f55c31d30973bc9b787050c13edb8e873d8b54" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string440 = "4cad33627c6f2cf9c1ae39d6fb625e23d5f32b41bbaff54e7993349371f5590c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string441 = "4d50951bb2357ec9dfc9e97c4fb8729c7a1d94b5d113683912469a7a05859992" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string442 = "4d967d51603e83aae994ae5354416bfb0867b27527da4fd94b40f75c2d3c641e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string443 = "4eea1e0122661de3208f478a47f1c09cb9480664712a0e34e753df8663025e25" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string444 = "4ef4954e75d38c111212488ce16b682352f7538fdf11eb94eac86ef4885701b0" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string445 = "4f050e27f770c59e8402d0faed061d0492b1d50d5aaed4f8c548b823dfa2dd09" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string446 = "4fa359eb9b1b66b9421ecebb27056254ec62d0b31a68a72284dd498380dc4177" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string447 = "5030143146822b7274ae44cab7267ee914c71216ac54e51516b0ee16f0d394bf" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string448 = "50760fb11c588feb1bd1134321070c53d5b67f7c151ecb37cfd5d8eac1900c66" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string449 = "511cb881123380d9b669c7664aeef8fc9c1ddd1417488fbd1da57cdf0d803c9d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string450 = "51a6d7bd756ce8d9948c880374da754b32cc907cdb2e17132f247f4fd888c6e2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string451 = "51ac0a907de53723dc23b3e491fae8179f0cd77084a2362f429b9f76b6ae08b0" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string452 = "51b43dfa1d70974cab183171c75ff06e39030a53f48a4a7dee31d392f34400a6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string453 = "52652191dd5bb9e3974cb1c62bc46968e94ad4c67b84a2a330ebaec19a0fd18b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string454 = "546c0fbbb9b7fbecd588e977612bec1b6bb1b3733c5e942e505a1b2b8de8697b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string455 = "549d16929c8125b4b04694fe39b663c8c4953d2905d188dca2e456cc595d5ce7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string456 = "54c4466dfe0ebd3de29706791a4cf961dea7b2ca7ca8c4ee3fc80fd4206114d3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string457 = "54e500e6a857e4af31cd8e2b26b990e190e497ac0c93e654ea18dd8f3d9fbf12" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string458 = "5511d77f4fec100fd2f4c0993ff991a2516a473033a18216ea54f0502785b199" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string459 = "559d2cb3e75785c41dea1e308eac3fa511ee44cfaef8f9ca6845703ae830edf1" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string460 = "55be8a40ac5f75e95f27147cba581018de3857140f8fdb2ad13016b6c29bc7be" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string461 = "560a6a33d09d60063663df714e535b74f7ce1e9fb8736ff768cd89bf1e333e39" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string462 = "560eff9456ec2dfd07ac44e6d9a79dcdc678d49a029bf3b0e7f75dc5bbec0ffb" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string463 = "561d3b61a103c4e94469ad8d9758f96676fc4fce3c489140f8c6864a8e4c55b9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string464 = "5627805837c5e8f2f5db7ae56fc3ccee6397c615c8458ae0285216588f5b8d7c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string465 = "56c212ce0a433a9077d17ead7c8bf2a52586c2347c7b2534e141f56ff6ede78d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string466 = "5767c1bb1b6d4391d8536b2c0736820fee8f7f1b0017c754a6ee7deccbc693b4" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string467 = "579e0f946f0d165567b7a8e933b6000368480ce09d51042e8753e4b389318dbc" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string468 = "583071fcb65b20e8164eb23a66e2147d7e7621bc944cbae675914cf23de98a6d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string469 = "585b1fd21dc719ef6cf74465e417e774dd3838e2cbf4e985da3f647fdc9674dc" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string470 = "58716a4f8ccd77613cef3c7872810b38550875b18b06677e7b9d7c8ae7e1d30c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string471 = "58ad0843f7f9e999e35a9f41aff3c5f67e63194ad08359b323923c2be9674d52" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string472 = "5a1a2900ec634bb1651fff9d542491221449754289ad5a58791ee3104ccef752" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string473 = "5a2b42f395e836e2de823d8a19acf85ebc580b9e6b44270eee5af0ba023b91e2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string474 = "5a58a6413acaa3d6bf69b32764e90ff162d2b8173e97376007557b2a23d90eb1" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string475 = "5ab9136f9d920429f7a993e7f0b6d18d27338fd18952695a13a93224f3c680a3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string476 = "5abf8e18a6a5c164568a7391b6379c9693cdefb90856ff19204a13d557f896d8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string477 = "5ac428505ae4b2a4c7a9b0a03bc948ae7cf0be5c5e7348b9f6303cd2acd8aa36" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string478 = "5ae72041c418f217c872a9935c29da95d0925fc6eca321e92e33bd60ae526b91" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string479 = "5b77f324911a4a03654a78e1e870968a7d61e9ea07435bcc9d47891523677226" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string480 = "5bb73e9a41ee1e8ead70ed9fd3e9e7f0a253e84cb441b8c7889825364b62041e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string481 = "5bd91a94ce7fab7461d6d88c603d94501bf3f7c8865a3a5045d8caa39d82ebe2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string482 = "5c4edaafc9e7a3e8aa07634eeb901be2b64b899a9fa018b5ceb4cb800f750d9f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string483 = "5c59a42bf1ad7c424f6c337cc11e40ed0d8d365c57378df1e5f5613223e4c1ea" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string484 = "5c9ce953e49bb74ead6c093ada4159c244082732eb00e00dd526e2edb0c820d4" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string485 = "5da0734623d5c9fa77825167f2d7f6b041d48087e5a93156e97135f68e4cce97" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string486 = "5de705eec2460c614edf09cf700176ae09ca862cd8233535b70f2c9d7307a8e0" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string487 = "5e155e9adb8422b5b194169e1819096c0877adf8b409a32f287ad82a55add44a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string488 = "5ff378d7374d099fefedb432a31052230322119401518b244a8b7b66415bc988" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string489 = "5ff9448bdad5a868174073bd76b1cbc27b434d1e54cb931d22258dd34ff6a7de" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string490 = "60505a1d3406e698abd0d1019aff73029d23af426a60672d85780d0f6517fccf" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string491 = "60586b8ebffb86b765ee2086189fa6e0e9e4346d1443e5c133fd5ae4e6b13277" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string492 = "6158ceeafd6c8eaed858e7f763b31444a2d7841a447178809a64dcb73addcf10" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string493 = "615e768522447558970c725909e064558f33d38e6402c63c92a1a8bc62b64966" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string494 = "61d34e67ae3b3c28281dd29a2a8dd90a7ee3924a2550a0fc7b8eb1c01c7f83c7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string495 = "62cca262256335868ec743989fd6afb8d53d51870abe9a0ef12413a82719f29d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string496 = "633009bda2a3aea268272f19eadf91df366d38bf84e76d56b9e598886d909fbe" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string497 = "63518ea48a4b0bd7a3750f6c67948316800e284ce9951e6901bacf8fdbb4dd07" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string498 = "63d02e75b729e2cc17604235cf9c0b506b3ca5d578a8e32a0e85e28763ca25a6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string499 = "641816acccccdfc2ed22e186d2f82a9a2c558617542a9e4b69b284a330a15daa" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string500 = "643d5833bf21a57f837071016958a67d73868d730a85b637ec71bdf3705068aa" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string501 = "6455615d468553dbe82bcea9bb1e67082c4d728939abb16b05e8e378ed4af09b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string502 = "65876ca1dde6923447642de1dbcc198b7f5bbe53c26d7eae7f1d675cb5f68774" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string503 = "659e8eac2bd33a73a5562f8af3abee9ce6dcd747abe0d52ecf63f252ca79b2b2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string504 = "65d4d3773e423e48fa467c5765c8ca4ea298ae71e0a0bedd387fdd3ab2989870" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string505 = "6793418c5f683d05f50c73efea706e93ab08b8027c6711cc2f4c8d8dbf91c439" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string506 = "67d5e8f4f9a37b6519c10921eea1306d9a33bb20f3b9f1b35cb22f3b00b179db" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string507 = "68218101d6c83cd34c23c9afc7ca2c7fa13a1bc8138481232a9410c5da4a9386" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string508 = "683bcd5fce3d71c8fd2c0e4c8a5a7254033638848035b25f04d82fe44a992e0d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string509 = "688dc9d39588279c2872574aceba8950660824d3f0b91c1c50e1be065b891f77" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string510 = "690e0cc55db7e3d5de7a62b4a20fdfae8c7a66c1218d57efe9d432521c031ecb" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string511 = "694f8c09de24e9b4b6b438020fea1d56c9941e9a2036d43dee282749a90989be" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string512 = "696f4e32bb16f60bee96bab7207e393b554bd64795e2be9ce857845c5b886886" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string513 = "69c4271ef4f5bfe68fcd696c95af04c90f3340e5af9454294d9db58410f45ea6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string514 = "69c8a35eb8a77c290766b74582cf485ffc73d81045f82df9805d4cd1c4934dfc" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string515 = "69e1d22a36d6171f98da2f56fa5261813b99549f1cab882dd13c62b4abc40043" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string516 = "6a4fbed745f3af1684f1636445f56bf65f02db3926d0e4f8eef2661eaff9df9a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string517 = "6b0a9af5eea28129fff4c32a284672000e7ac7d968469d23c5aa341eb1eea262" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string518 = "6b546e78cc7821b63192bb8e087c133e8702a377d17baaeb64b13f0dd61e2347" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string519 = "6cb8b44918b571059ba3d3fd542a0fd60b2bc850d999d6eafdd80af061818bec" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string520 = "6cd6746c91e7cbeed9a2abc1b32dc169c5cac487b896033e54f128dd0a960db5" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string521 = "6cef3ca27cf61c96477576ca98cd658b0a2b1c06c6628cfc6a36ac7357783738" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string522 = "6d3a0257132fce02f5dcb7d7ccc7fb73db233daae688ebb01de0129d4b448998" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string523 = "6d5da6436d72bcdffdb2e5bb5b0b20ada0c23d10c1fef1080795c86e51509fae" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string524 = "6d60cf4588ebcb6070f39b0949841c1ee3cc5f05ed72e2820692d1b53808fdcd" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string525 = "6d83e7f5c378f8596963e4efbfa9a8b39d183ad21134f8c7dad81ef40c7be9eb" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string526 = "6de3b230db2fe85c44a7250e0f9882599ec706d0e360ccad805f311d0e1fbc14" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string527 = "6e5529790d78959b5356c5ad366a91d5d5662267ac1e78eeb33498557efc90a6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string528 = "6ea5ef1dadc07545a736c48425df63f6d95abd70ff2bd41975948cd5ad5e5788" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string529 = "70920ad4b6ad5aa2ef24ec79e80de4f32f79b2cf4c1248c94d90456b8f269951" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string530 = "713490eff933ebcb0ce0bde4429f3ae4cee69cb4663d5172c2242738f97f5a4d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string531 = "7236273a942e25e236e68c1010b9a4a890bdcba93aa8d41237e70422203e4020" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string532 = "72a7649ea0ac981b6bb32dbbe52f3dc76ffc61c10f0e1ed04014ffa8525cc231" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string533 = "72e57ac71f5d1bdb6b575ad08a0677bf555fdecdc30469f0b41fcd6d7272c1f5" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string534 = "73db8fde14d109514c0734b7852e4a4307b5b4cc4cb6aa5aa15f601359e88740" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string535 = "74b7b34bd0a221eaaf383ef8a38f41f466166c6184d6586f510cf509e9e52f0d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string536 = "74e099d670bb7ddfbc574029735758bdd1e0abd82f7ab428fe2118a8459328c0" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string537 = "7506b958b82c26e3c9a5f11c36cc63c475434e28de8bd501d2823d0decba29ab" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string538 = "759204cec7f9891cbc44845bb8fa9976691ed4be2d356db0d15226548e1dde4a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string539 = "7648b89b79e72510063a89ad60d807515bea5b595d1dac15891abe1981484e65" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string540 = "7659d716099e476c563374bd557a93f1c5281844ebd93900cc2f97bc759744b6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string541 = "76999803e6f8b74f33be250e048d6ef124925cd8919d57a22feef1ed5548a7fa" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string542 = "7728f463c0a51beb209f57662d104263852cfeb2dae58e5903eea3e2bcaea904" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string543 = "774a849a2238d98f47427589292c7d1e95a3777631f0afc8787f0a32b0dd2d03" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string544 = "7778bc98c2588b9136c61b72f7a4120c418ccc2233e3389f239c822eca92db15" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string545 = "7785670d773d00ffc6e223c4c3ccb1ce7d714204329b12536fd128f80fdfcef9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string546 = "7835f04904af502bf964096d69451a6151ceb600fa2360bb70396054516847e7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string547 = "78f555f713f391ee8b47078dab69267e837fffbbdeaa8e46c50be0e6336102f9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string548 = "7a1090e46befa253c4f1cf0d595e3718fce05aad37b08107aa02f0d40de3347f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string549 = "7a3a2f28dde73ea7c3b19c7e4552185b9ff0417b2bcc8c5daaf4d14952559fbc" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string550 = "7a4f600a398bfaf6e212a43d8a41a279a97b84b15308b7db0ffd2f54b9c117f7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string551 = "7a69466dbd18182ce7da5d9d1a9447228dcebd365e0fe855d0e02024f4117549" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string552 = "7be230cab89ef568b598e64885fe315c8983f300167a21b8279cc94cb99317a0" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string553 = "7bf1a774419d2b7c7dc3d1d61802494c5b6c1a2a9e0512f2a9993c73f41aeaa1" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string554 = "7c1d37a17c8b71a2c58e28251bef0baee7b06757764e5979daf7f1185a9696bb" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string555 = "7c564e21d505b73cfb26be1cc3fefc72a78787e8ff4dddca0d1fd7923e00add8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string556 = "7ce39a5eee1a1a1929de2abead9ee1d5a4182978cf6f2e23e30e44784d2c47c0" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string557 = "7dd6329b978fd795c42131075b4fc6eaa16b759594c8e80402e7d8221d6c639e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string558 = "7e45d5def0e8c355baf38688273584fa1e9e5c2d245d1535b5c965ce568d8a13" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string559 = "7ea564978060c0773bf97da056d612768bcc47cf4bd0bd7b1a98c5b61bd00af1" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string560 = "7f0f9593260859c0e292aa1b76d618a71c83a1d26ba802ba7853f4637d1922e6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string561 = "7f21ed0e3b0f5dbc1b1415b85df5c0c125c64aac320d9f23de6e120ab2285110" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string562 = "7f5bf0735a01899a8420d4247508aa7f09af346cb434baa5cdf024200ebf4f35" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string563 = "8009a7f38189b6bdc8e8afca6fc2aa27ab1ca09525e36e3664de8436b78cf439" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string564 = "80f8454777e31fe469f71f99f2df69a00f79cbbb42699d00587133516eb90546" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string565 = "810a727dfd8127c192729f6d06f0564300ada683063d0a8fd622e2b338714514" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string566 = "81e2c46d9fa49c65a9ad0ab69dd121b110d63dd12242b12619b487532a6fb6ad" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string567 = "8231ce10a57076634d408749cd0a06eb178c2f0af84ea8d7284651bbd8320c39" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string568 = "83dcafd146a5581427747c502219d9dd3c349ef673689c02c0ca2325256d3490" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string569 = "8411c83668a5bcdf0429fdc06ee58ebd41bbd537392f2979e3bcbbe2afcf860b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string570 = "845cf04a125d951c0b3f70f2c669b3b1277c3b8c4c02fb91fc35e84581f409d1" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string571 = "846f9e23af79dc84df9d197037e933dbf6b2bf068d4406bc7b3289cf516f71c5" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string572 = "8529307629293748098f5a78900d1685d70131e05d2dc399be5701a89dfb0a9a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string573 = "8691d8707e22f82e78e2bb5b6c5d8d600c9b0ce70bae4e3cb0b26acfde08cd62" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string574 = "873b9cdf08884f8406ff6d65e56cbfd2a46c56bcb4eb789fb9e85c34907fd748" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string575 = "87ebba9881dfa1757459d72857e2f03132b83291e29d6b92096e9ca3d6dd14f3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string576 = "883a4ec63fe55655eacd7062f2920f8b3a9bb89c8ea4ad8f9b02fd7c2f6f3069" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string577 = "8897b01cd05406b33c497bd06f9bd278726ae9812352caecdbc8528dd630eb5e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string578 = "899f9cdb99255c88ba4af54556c52f24d5ef0c6911663efef02ddd15f0934409" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string579 = "89e5abaa609aee8b15058958c28b4821708fffb607202669ef33803cb2a80104" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string580 = "8aa085e49959c67e804b50f07be758f3b9bf46f3da8a0e6612d6bf4f089f603e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string581 = "8aa1f48415cfbe283b446c451d7c834234a9e6cf564d0d45a2803ed7a739c4f8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string582 = "8aadca4c38166f4dc6f70126b094c2b86d7150fecf48bdcee668cc29b35001df" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string583 = "8b7c731bf78f3cf4972a8197d3ae0d4b27041e4b52ff7e6451b826e2a77fb06f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string584 = "8bacee16a0e720e6a97e27f340ae68ab356828d06eabc6369119e52ca428f6c1" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string585 = "8c4b014b68d484905681e4055a154490ad2d48b732022b35eff98ee94c4d8232" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string586 = "8c7137030d9653611f63d82c0dbc8354ae13a1e601bc86e94ca83fd64c28f274" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string587 = "8c8f3bc0d9ae33057bcbdb5e048691411bcefcb5c09c61951a7675237aa91b67" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string588 = "8ceab34777527464cf217e5cda5008365e1a5c1c2197000bda78f303353308ac" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string589 = "8d020f5a01e88c58f0ede5b1f58e63f30a170502c7a2817c86b1f97832cf515f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string590 = "8d7640bff1eef0a194fd9fac25355169433b53f6cc34f3eb382bc47aa448bd19" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string591 = "8dbe2548630f7e261f208f203dcb96aa9bab12432a9e7c8ba49217f3268c4c24" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string592 = "8dcbb18e02d5be2663448810946eae9f1618afebe35d779699afc9ece1bc1fcc" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string593 = "8dd9febd2c4e197aa92735534aa84b224afd75366b325430964d19bbdbe7a4a8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string594 = "8ec0be6f26497c4abef4cdb6e2eef4aec30f8cb2aacd65f200b7cc6daba26f0c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string595 = "8ed72e4fc14d2a4bbb9d52d5521ebbe77d2ec46b5469d8e25c5965908686c7b7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string596 = "8f23f05d5f97707f4e3e4d90175a099fb924b07c9ed7b81e3a1b8d4bc1c471df" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string597 = "8f48fc7f2b40dd92fea030c044e9d48035cf6a561b3a09d02c161bacab0f3c30" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string598 = "8f4a61afd9794d6024f42008417a94865d1912b5def2cfe91ea10cb60340cf8e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string599 = "8fc2d1718acdfb83bf620dea1f87f053ad99f609b9881afe70913c6284543223" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string600 = "8fc8b333eff4c9c189b5843e20e749cb0b67cba23f8ab993cc162d4c8865ae4c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string601 = "90286bcf91af16552af2fb7aab0007d06a48493bdd2cb3b7367c7e540f70596b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string602 = "912a5d11b4160a54f83f94ae434abb5f5b85915aa208bf086195a57ddaaee651" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string603 = "9131d13db3cdf4fd6578488dda52fe4d714f4d20c8266f22d1113e049f1e4a53" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string604 = "9166f6777dfda8e6ac74b2427a25f6be82b6ad43079ac2ba4c56592c2ad405f2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string605 = "91df836629d68a22c10f485918c2c0406b6e5d12a21f3e8ae3c7baaa0301ee46" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string606 = "922eba3a1f3bf78db513cac0ab1d959ec27bc1879794b8eead2fe6e346be060f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string607 = "93567450bfc7916e8468e4c6c0d1792195fe70e0138461f98c75ca6c5d2f76a1" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string608 = "93832ebdb2391eeda156e8b58a0a5af6ed3897b5d9a90b3d9e346a460f76dad8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string609 = "942c4cbca688c82a6a6fad58d9b55ac261a8b73b74fc5e0484a86a1e7f8dca35" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string610 = "9466c85da5aa10d936e24ed74979d26231633e2d449386c4164bbcc4bbc313aa" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string611 = "947d0aebbfdfa05a00d1cf8e087b2f93a411bac74e125da4abfaa2e6ad3f8826" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string612 = "953e3673f6aeda854ed73b54de0c6faa1c38ea80e6b13b3ea010bb56ad79cfb6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string613 = "9549130cf3c479190977cf265b672fcd9a6dcab81d085e01d362eac660dfdd39" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string614 = "958af18a7de60d885d3f792d8a0b0829aee5507cdcbbf2d23208e45c57239727" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string615 = "95cb237e34c83f5922c36da70cf5e0b2e1af5729322da2c45be05c107a0f9ab0" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string616 = "95f159db9ba6cbe6219d80ce17e7360e5906094333cc595190d683a45d9911f6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string617 = "96a9a57590a8a235b89ac16face003d83198b27e6841fcd35de89f0f710a226e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string618 = "9711738fbc89cd6b37366690193dfdd6402af920106426ff9d33aae65eaba5c8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string619 = "97ab5a4ff291a46ece4aebafa570869cbb74a5a285769c641c257cdbbf13744f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string620 = "97d14bd510bfca62bca0d884ad7953e044355e4d1cc198471b678f4201e5eb02" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string621 = "97e2d2cf16103f9149b1fcf33d5e982fb9f37f0bbbadfe787634b277b5f65f78" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string622 = "985f61fb06d7878172ab9e204eb42ddb76d299c69b7070c4abb26c3ab39873c8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string623 = "9877b56ae67e7621ad2dddc906db9e35eb13fb7cac6cab92b1931d6bcfe9d3d2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string624 = "989e7ae1b470f2f483683ff46c38dafc347b6a541d3054ccb8c1ab5e208876b8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string625 = "991f1ee0d29a4829661bd53b2cb04810c416466b74b190e6627fe99367ef24cc" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string626 = "99314a42485888cb1cf7197f43bccc1d285b116f7ec936fdf75a354df21376e6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string627 = "994377bab9392a6bac39023cd24df98efbb668cef42ff5bbd709a165fc7a3fe3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string628 = "994ed2ac2d66ee84fae1b9b57e606ddd876ad714c3fb7a4a882c10da7d0b2332" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string629 = "9968434b0a2d9a4fbc85a732f8b5feb3937a9851e7eb4491966747ea188746da" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string630 = "99ab49eb94283378c7390bae6943b7b699ebd2ef3d560e5892967559e9429b7b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string631 = "99df34900abf7cfbf9dfa5d8f04b8693175e0e9a4e79a85677f393232bad0e95" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string632 = "9a0023406283d9856b07b2d39b4444130001f86131841df2eba206f0ae379b6c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string633 = "9a85c7f95b97a65e72b0ab3c2780b0fdcf753d8997314f0aab7b11e9e31cda35" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string634 = "9a872a2424ca1193c32e55b9bac11c09ba29d15182ad89734492c5193fd64d55" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string635 = "9ab40ecd7212576f2894c9e3d2eff74c62554e3abab7453c8edd7a7249c8b3f0" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string636 = "9b5609bdc5e1b30c20848a3268d4722d9e9befb7f1b620b1d2bf9b89a3429e93" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string637 = "9bb578e34921df2349f86f8867986d15cd2ed3bc510feeb6feb318493e753855" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string638 = "9d1c1b19e41b7543be1d209d368bbfec5ca14e413fe1b060354a79dabf29f727" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string639 = "9d31cc4b07fb3b4be9ce62307c24acfcd5f13075723eb621a935d2a98d8e2f35" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string640 = "9e0f93ef74347d1d494678f3eed8af14ac53fcf3e28349fc277f552e0fa6d984" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string641 = "9efacd75bddef7424cbce62a44bb6f94e7015af799301f19da01c6ea72fb2481" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string642 = "9f0a2fc2267823c55250c5036b3555e8e707ac274252a8c9fd18e521c8e66287" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string643 = "9f5c55028eb0ffa7dca229018a3fd7bd9eb5866449245910cce6f2695cec37d3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string644 = "9f7f5e0e8a05792800e0c53e361607df2359b6f1d21eba33d124ff44046946b9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string645 = "9f8e72805e95575c9875ba19a32fd3506c662883e35afd58bf7ac9c15e4088c2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string646 = "9fa4e7fc4ff2efdc1fa89ec084b422fb8b57844a6c155c92a897767e835731ee" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string647 = "a071416b90984cabb06774bb2177d004798c40b52ced3e9604af9997b82838d7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string648 = "a0a87215fd80d837f4825deccf302cb0fe7184219580988194789ecc1d65fc1a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string649 = "a0d8d1a6146edb9a3e05ed28f1069322c094145fbd27e1864f891d962db6be54" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string650 = "a127dfa17e403f954441ae42d4bca8d2bdbc2e566e522a2ea75d88722540efae" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string651 = "a17a13c48d23f7010a1da7f4be455dae938db574ebbd7882de649792f3959df5" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string652 = "a17d3b89f61fdfaa034da9471ede5e346af8f5ef897d792487c2a726a071baae" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string653 = "a1f112b27e1d963f44316f29f6656a85221e6138afcb90f5a6bbcea6525b69fc" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string654 = "a243b7196d9fb7977aa29002a42977d87b1141857421c8b5a4b8b3ef3a5cb59b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string655 = "a2a63c273505a6ee6580bf6d77a7c510f6fba4496e04efd6656f920b477dad69" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string656 = "a337eb11ea8a12ec4bfbb0d1a3f939fe6105dea0836b5f9a037b67fa4dbd0b40" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string657 = "a492bbf95a3db658f1f1114789c481e91374623bb6484c998e1f1487e0ef717e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string658 = "a4ce76854c9c0a5ffd167bfef3e659a95d37d605767b71435b7539461e3185ae" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string659 = "a4d2d5e38ec0bf86be4572151ceac1cf5b8eed54eae425b89f5274ee9dfc331e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string660 = "a4e7ad2bf439d52663283ff7925e7935d3e770f95fa399bb99aa0adee0945c59" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string661 = "a516bc50f144f04756e380fcf24791cd1851a5d3856f6feb66e509ad0f087536" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string662 = "a548aefc374dfd65cf3a1970eec4bb96111c89f97716f3b30fb46909d24436b8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string663 = "a585d145f761ab45a617d83aecb895a363f95f5e282f549716f8397cb8006cb5" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string664 = "a5b9dc00d9009b755eea768d19d401d268a2ef7a7fa9dc7bc6183064a2d8f40a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string665 = "a681dd702f47215b0bf02a6f100f677d006f1e674c56519e39b888dd78779b40" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string666 = "a6f4ff21424c038ace4944d8330ba61a0f87dfa953faf7349992ef08a04f5bdf" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string667 = "a77ae629a1c7ca5f0be0d4d4edfd2198914db2ff2963ae1f66bbc87fd0b5a4bf" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string668 = "a7d587bc5790f34766ae32da9825e585fea77ba0b3f9ab6a3b690959ab6f2386" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string669 = "a845c8128bc9accb902cdeaa85c93cbf41dc83d74ab4c82ffc13f336bee6e666" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string670 = "a8bc3637b6ff70a1ed94a1b39c54aec2c212f8a657c674987bb92312816938ff" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string671 = "a94a0ca227f9719af8f6cc3c505fba9a63687013f513f6b8991f4f036475740f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string672 = "a9b1d358b072c89b85d9d83f024233afcb32a226fa25ce0c10828db705a10dcf" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string673 = "a9ba6f29ebb95e2e65f1e05b0f61d0a32a3bcd64d0589f35f41b69ba02d54ed8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string674 = "aa5292f60e239072e657cd3a1ebd9604018aeeefc0835d4fc691c53c8e01886e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string675 = "aaef424188f507186ba653af6061eeb2308ded4c9f56716239ae667f9ddbd761" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string676 = "ab0ee603e53cd0b32f09a0c53469d09281002a783d8aa5fcea1110ef2b57df81" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string677 = "ab2c849ba04bc802e0036244364ca131377aaa5311771331b64ebb1b02abc4d8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string678 = "ab4ecda5fbd41bdd97780885ba1722c096482eb3e71caddd572de82c42b28aa6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string679 = "ab835ce740890473adf5cc804055973b926633e39c59c2bd98da526b63e9c521" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string680 = "ac13e657c6b4d2526c00443025cc5a142439b952ea269e20a2d64fa2da712c42" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string681 = "ac22717875ec08d5ca32ca6b1846917e63f8a4db4de56138f782ac231e9a784f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string682 = "ac398617ce13e70e253f59d8d41c1c3c0f70875c6acd40634b1125d9a5fc20c2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string683 = "ac6ae000d13f06fd4a0f87af57a2dcc4559fc5d5aa4cc7a1606139ffa85cf473" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string684 = "aca998015730e52a8f984a025bc4cd5ec31b0aa783828ab1a6159d7082aca0e8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string685 = "ad6e6b33e48ec8da3e59868731d700938add9cbe26687e1555028a04233a4f43" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string686 = /Add\-Exfiltration\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string687 = /Add\-Persistence\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string688 = "Admin, your system has been hacked!" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string689 = "aebea2e78c57a1d2e961e1d4bf534be7de985c64a36801d292512be7ee70c3c7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string690 = "afebad2b0d57634ed88fbadfa746b2ca9022622b77e33d49a300b62e9821e543" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string691 = /Ani\-Shell\s\|\sC0d3d\sby\slionaneesh/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string692 = "b0dfaa9226786fa467d758760aa766da96b58baac3e7fa446c6870959d6c4602" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string693 = "b0e02a08da80d249cd96bda183d2910fc02c55ffa72cae261496d520e857a5ed" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string694 = "b17483ad91b189bd4ec7229fe188155f8c8deecb00a44c1016f1e1f36d454689" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string695 = "b286fd04310a342dffe4306712f8d0cddcb3c44e8c0c07e8be14bffc87cd26d0" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string696 = "b2b8156b03d2f5abf54642ed17a3d128598debfdce435fb61e5572507d1b131e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string697 = "b2c88487cd1743d186abb8823fdcc4046afea83d850521aef26f753c1c790d7b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string698 = "b321b10726f3cf1152c5a613bfd48a215518410179ae8de59eeaff0a141aac38" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string699 = "b373730fd4b62553b6a5af092835918243ea29bef6f559849fc8131c935cb6cf" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string700 = "b389754716da0100ccf85c210ac5759b57ad364cd13ef5feb7dca7c53627075f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string701 = "b3afbfb23b2dc699e008d6331bb6548ca2eff4af4239eba06e55112338b7611d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string702 = "b3c6cc7abf073f7d2faa2ba4212f7b2fd316c50cd07b9001eb40ca73d35c7128" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string703 = "b3fd7e46fd54a5a6271012b29414c1ed3cc162b942d8693b88fff76acf312277" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string704 = "b4136c74ef7fedac0f8f6f8261cad1544902d0c786ea3ef1cfade20c07a5e82a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string705 = "b568e1b6cad25bc604735e958975fd0471c60ddec52368f36e204f83e8cbd5e1" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string706 = "b57bf397984545f419045391b56dcaf7b0bed8b6ee331b5c46cee35c92ffa13d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string707 = "b58d48c4e18ca596bea2b23eb26a6fde046f71fadb6f179ddf6734353e5e00ba" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string708 = "b5e44b2b4b1775e2effc6920974850cfc576b93e30be6deb0c15a1a0bb144571" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string709 = "b5f9ba7cbbe38220138a86b56db4acec50f670d3889505382429c489ec908214" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string710 = "b6a255086f4aefbd0e8b4b997b146dd95b04eb7c095c21c3269cdef16f538f3e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string711 = "b6f96297c1c905e32413c6deb7e794cb8a1af37b9295e5cff257a6ff063ccbd4" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string712 = "b7353069ada87797ea078b2abeb93751bb907edf28ecfa3f1479bcb79f16359f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string713 = "b735a1196f7a065564c3271323918fb345b4865338093eb8c9fb04d5840c8352" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string714 = "b7f00ce7576d810f2ccaa6d31767672e94e50e3ffec2eee2a2ff373aa651cf72" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string715 = "b80125fae6f888a941e421e929bf6837142d0bf30f13fe01c266f7dd05e904b0" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string716 = "b8fd450e16610f3cc307e7b1b3309ad4e79456860ec16dec1006250b8afe49b2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string717 = "b93d9656d13b3867ba6e27f6bf529d394558e9b555d7564664d50f63cc361864" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string718 = "b9760df5de508a4b3b655a3de28ae5ab271d4189299513c848a033f9480d5766" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string719 = "ba052c32cb079708df013cb6801329b186f0fe1a4c6e1c134e839a795ac6bcf9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string720 = "Backdoor Setuped Successfully!" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string721 = "bb1925f0abee8457796b7fcfa310bd00b37d46158c4f700da25a57ab062f5107" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string722 = "bb65c7f01b9110e615083a0c5a02d324dd0dcd9416bd9791b4fc92d284cbf206" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string723 = "bb9699111559e3ac8e2739160742798aa113f5ad994e6bff78b1dc6d999c4116" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string724 = "bbbf3709995e0cb8924bc07e857042afdf5a294620c32e12136805ed6bb8735b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string725 = "bbd92565c5ec78f1d2935a02745d85bc09e5b4624413cbc8fbb704c611b98050" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string726 = "bbe1978fae7026d7eb9aafab269fec0780e41ecccf40ad03dc37cc12653c2c14" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string727 = "bbfc6050331bf5adc5739601417028779f7d971915cf97d7052b9d2f55e06302" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string728 = "be6556cd585cd39c332fb5ed6881b5766af3bb01d0276835e172e81d04f06237" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string729 = "be7fdcbd1dee825a6adba54c5f2b72fb4000cb474c834d07e1f0f293d54e1f58" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string730 = "be93d296832c123ba18b2f43629dae79956b203386edfef96e180470259fa417" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string731 = "bf3aed0e31aca1ff3d43724f9f3f8248396a9cb0bbf234c0830b6a4999570d16" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string732 = "bfee4c895d0f713cfc7c1a2f967ad8fdffc92c470e0edb8f0125959514445138" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string733 = /Brute\-Force\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string734 = "c0067d058ae4086ba276aa5d712782428fc0f72dff4cfb67f77c3d6ac08f9fb5" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string735 = "c00e8c409f1cb4e6e7e8bcea0a82212714f6d80cb961b2f8104c5df89059cc69" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string736 = "c0342fc8e521fa627bfce4988c83a081f394d5587fafe3fcd6765e028eca682c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string737 = "c0364bda334fc6450e71ddcd34eaace70089c2e6d69bdc324ffd144ac33c0c2d" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string738 = "c0a1ee50bf8984cf88c85740870b39f378187b877f728f0aebcc8d8aba03df73" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string739 = "c0c3027a8c08212af54ddfef22faf33a5cbee35c1d6ac2a44251d9e3dda42510" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string740 = "c0e6f80a5ecf346f09432ec1dab7a23f6418f6af022020420330a463eebfabe9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string741 = "c1f6cbbbf283dd122b10ec6bfbda0799703bea9465efc5673e71f7fd6951be09" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string742 = "c24e0fea42a4e92ab55ff814ca3c5691a9bd0cdcd923db5ca96862a580757316" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string743 = "c257234e783ab69c48d2d5b9b411edccfe5b0b1d7c2aa96d77c34e095bb88ac9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string744 = "c26e4d825f8e7f7ac40efbebe1302ca8fd4a5b76b3f2969ab5cad764565dfc9c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string745 = "c28894e4ab24d142a072fdbfddde4dfbfcaba9bfc741a00e935e596ac8c2b3d3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string746 = "c2be7dd40f08c1696c4971e9adb2ffa6b5d8565199aedd952c5e7238e1ad08f3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string747 = "c2cf51bf8a314ce15a028b75bb2b29f386269608c9bff979acbe9692172ee6ec" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string748 = "c310f4109a827b1023e2398cdeb50f18a6620643360065369dac75192aea8420" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string749 = "c3309f36c390a33a6eb46615bcd662c76e450b18d24fcb0aa8f1178f841ec7ad" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string750 = "c353e6e63ab1b6ceb3c715db4b053d9b112b86b680c326134514b136658aede9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string751 = "c377f9316a4c953602879eb8af1fd7cbb0dd35de6bb4747fa911234082c45596" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string752 = "c390b9308e62a0f72802c6c7edbbe83e35d893aff632c0f332538ee263994c29" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string753 = "c3b029e9e7077164976a5f73399b07dd481ac41d524328f933a4cd62a36af679" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string754 = "c4375226178ff89c7d58598072dce4ab139c71fdf311071936d8331dc11cd90b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string755 = "c4b86273fcc42e5771b3983ef4150b9818f0038a7df0effb68ce1303c1459b73" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string756 = "c526a60222848f43e3d11b9fceae6cab1e9e414b490f8247ee95bff8a864b61f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string757 = "c5512b0f7e41dfd3f8a5c0dff6910509a6cb3e4653a87b3d4daa402d7b40bb98" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string758 = "c59bb1299b1edf20518ae2b0775eb56eae62a77e46dc3ae45560f47e0af39299" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string759 = "c5a8a142728c93974f8bad555cf988db83be078e17dc1ac591fa3ff1303e852a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string760 = "c5c63b3a99d3900dbeaf864cadeeff7af57fe293aae39525d4f4eb2be118e3d7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string761 = "c68f85a725ff87d40c7ba00d7ffc8e205048d8977a273327df653821a8a06e53" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string762 = "c7b76c0c337dcc31eeef08d0ae74254b810f5e0aac54a9ff06c6f87cef8a1436" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string763 = "c7d4de4e194b708aab0871da2661efd18074a9899a6ea784a4c7695ea5ae3c88" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string764 = "c7f3651ef551ed09c01349a493760935c2e22c36934e7604dbf4d61e2f0797e8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string765 = "c8ae4bec1bf8a1f63364441f766287ead235ef96c84895a62e07d9a9e7f8e6a7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string766 = "c8da2ec07d898ec888a807d390929697de0e87dccd27516dc190b37c64cb9bbe" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string767 = "c8f180ed07a027942370c5946ad38e71f4afc3a1cd10295b415606678d9832b2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string768 = "c9574e5fa7bf17835ec454e507aa359f07fbc1903c8cb643e23e81a2614150e8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string769 = "c99shell - Edited By KingDefacer" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string770 = "c9c4b50a5eada9222d7c82caf9986fba3491dc9f55e8bdd0df2b8893936f4d98" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string771 = "c9cfc822e5fe51fc15df971b147acf9cc5c572c026cacafbfab860006e39404a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string772 = "ca541408d19d557cbbb2c099082190a61814e1b39a0fed6567fb1f473cc780b3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string773 = "ca5eb2b6344df155fa10a39bf815f65daa9663250e657a3e1a8ffc4416efe778" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string774 = "ca60f4e33d70143b3f928143510d75e39c20d35c1cdf90ee77fbf76928eac3b9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string775 = "ca9f976e3685e42d665ae930876aa30ed3246882a002eae35469520ab38a6b5c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string776 = "cad7357cebb65176e5ea24ffa0ef75587ea700e50aa4bf0db182e673f458ed76" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string777 = "cae8ce4abd220828370284f9cb4b66aeec57aa3d9fdd34a47599b10cead0beab" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string778 = "cbef865bf615c4848daf375557669dcadbd531b38f9335b11b411b3621b8a6dc" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string779 = "cbfccaef2077858123b86e747227500370be60843d0f0c4b65a8a2ab644d707e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string780 = "cc53120b476000a0d75242ec02ea715ecf9a48386ccafb31e60d481ef267e707" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string781 = "cc72ad7e6e7983dac3a4407002be6b88afe56a73d887a58137963aa56216f110" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string782 = "cca8ea4f924ecc36731feb68313fa716881065641c2dd1a9db45a687d1fe0999" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string783 = "ccadc33019cb57a56a268d0d6be1a9e242dd0881dbddc06f376a06c7c5846ed0" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string784 = "cd73e2b32de14c58c3e27d833be05ec7fbfaf569ed10f18d47bf11352d6b4954" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string785 = "cdda315a5a89bad7451e3f921c57c16cf0d121f2599e1d5595be995ddb4836a3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string786 = "ce07cff17e7a4c5ee5331823d8e664013500cf83e6783d720ad7f09160712229" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string787 = "ce43f1e8e27c93b61b84c4024f7f9321c2755d6a5fd679f4d8324aadfd7ad76f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string788 = "cefe3493adac8a6a93651d2299547c1e0891897522f2f1c4e0835ce577e60632" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string789 = "cfaeab5ed1fab3145ab6bd8ceeafa35b7d7b10851f949d6c20fde81d8b4d4782" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string790 = "d172875534019a0aeebe70a021121ed7b5a21765d6d24838b5c639a1def0d59c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string791 = "d18fa52fdb740b1bbad14af154bffdd03ce7afadecf3df35b13e28a535f62067" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string792 = "d1d6193bb15e21797e9e976ffb5aff8f8edc4fc90cccb4667fcf0cb168073ae8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string793 = "d1ecd1c7f986326c33be2f9d183e60855e769cfa763f94906c04deddb3d78756" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string794 = "d24b17b869e71fde4c815978397d4764bf749e71f20dd1e6f2386fd0bad6b660" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string795 = "d2eaa9862ed7aa1d38f19684757cc30a8f7b9b4f0fb1bd96d6fff0948c7326fa" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string796 = "d3099edc6d73f362aa7672cfa3d7e0af5254484a4af0d5ac65da2eae8c229512" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string797 = "d3e1ab57a570a8853f6ca82ceada334f8e909252cca989451d201ae14cd178a4" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string798 = "d51cc14376f771812ed23ed381377da238dea6f9f768d767c8608bc03c1ff0a4" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string799 = "d572fb79014f9b3a6595a71f37eb4bb3a34ecec79c62ef053a70f4b47ba13411" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string800 = "d6658fde26b809968ead7f1b80dbabe0738ad07a6906ab5e809e04aa156c9566" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string801 = "d6bf093219aa31e78949446443ddda4efac3bfabd3f1d19222a9b394cedc1a96" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string802 = "d6e360d8a78cb4495df17f401df3a5c11d3ae13e46ebe7d94007bfb1d263490c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string803 = "d739d765024b9a15d65d07e64a21dc0796db4951305ffb864e9d7f781bac6b81" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string804 = "d77f3332083ca55d0cc730c39970b6413430e986c6adae9ece72cceb640da27b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string805 = "d7a5cca2bdf63841127a1618cb25e8e9a5892269fc687ca9a795b895bdbd4ed9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string806 = "d7c63d43b5eb3fa7f99253e4644bf7525246c13238d6ba5d020e1e25e277a133" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string807 = "d906be8835b28606430351e62d19d007371cceddd480522ab2469695772fca60" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string808 = "d945ab8284b62d5c8471a5eb71a852ba36b18770a7d334c952eb8367daf11e7b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string809 = "d98257f09b98cbb4c3241bd07a49c3acbef8face07820d52ffad0ab030c9a4c6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string810 = "d9908a88e10620582a234427cb1029dbc914ecce23b98f95e065d25ea08bcde2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string811 = "d9a59aa8f8ad46ccf0f3a9ed564c3774ec4d7153bae8795b6668e9b850c08533" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string812 = "d9b2ed1ac7727c0ca511742ff66c52de2adc1f8af1cf9751c9c3153233121ad7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string813 = "da39f93031e1ca0bd919e5a062b01d0bf39b52e88919ebae40a1379523ccab37" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string814 = "daa2d41ddbb72ece740bda89d16858223e9549977a2f0bbaab9a48c994ebac27" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string815 = "db5670eac95bc3149f2cddd7cfe41b2bb35b6e8af8f101c86a68e8da6d2e02ff" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string816 = "dbd96cb386138d0f8215e5a6d0b6bc23aa23056385a1da5deac1b8134d6f157e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string817 = "dc2d30a37a77a23ba928d9191bb54740f760396b46bb862b841bf22b857e9884" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string818 = "dc89b02f14f9f44483c863df6965528f3f7f1efbdcbe31db757c6a295e706b33" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string819 = "dce55c6179bb6f63cbdc3da71c057970fae70cdd66a3fdbe5caedbe8f130e2a2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string820 = "dd16f575d6e76269c85b00dae2602c43aba8c51dfd2106c744e1fdaa2067c81f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string821 = "dd8e3e6e19c02c8c43cf136edcbc76d38de044ad572198088b086e04a04360b2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string822 = "de49e60f2eb443316fa7585f6621fa83a9a3bb5b701649e05117ff4012379c89" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string823 = "de53e80411d94b39ea18d9f98cbb1bd6dc07ac2ab732753dec649fef458f3aad" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string824 = "df00930aa6c14a657802dcc5f6d397038ae4c8206bfef8a810a6fa7530fc6521" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string825 = "df3f055a2fe6f5b84cc062ba3576864810034bf5e5f04235356374b6e725f8bc" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string826 = /DNS_TXT_Pwnage\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string827 = "e06ff243f2101ea3fd1ff5f69109896d56776bd5d92d62e5607f12c693ece5e7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string828 = "e07eba4d775523eedeb78938ddad86e13e409ce0d15c235e81a02f5bbb0124d7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string829 = "e0cfde420c63408cdb09819c3d98d0e96356ebdab6389d08fe695846d51b3f9b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string830 = "e0d5171c6951b726230f5f811f202c3a15b3fff10aa44547821e29d3b13cc140" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string831 = "e104cbadc6c2d170ca642537aca707b86a7947df0c619b08b9d35d3c13c0e079" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string832 = "e14014dee6af3c42ae29dfc7eb3eb03790020c3c28aa5262fffe4a3b93a6df0f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string833 = "e1442c45400be7b8c2259e67c8df86c687583240414d8c1c085b69ff3493acc7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string834 = "e1b5f5c1f80865429429388b5d20c8b536b62b4596f19768bfacb315982697e8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string835 = "e1b86769bb6117e974ed565ca81ee32307d1f38cbecba8495e97c2555197d090" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string836 = "e1ea0335cc65cd6ab35fb804fd5b5739ae1b26ef43be230a24113475edecf6bd" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string837 = "e21059349b25d8158d9000d34dc6b296e4a680c7b613ad8455bae2df118d7dcc" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string838 = "e279bdfd5c0a7c8782255f9c144d85635054f9b26db4909669d80ff1cd853893" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string839 = "e2e2086796947124cf0dded1338a6c1d86da44ed72a7bb49248fd65e491d88c9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string840 = "e30bad2f0453e4041755190c7a33df46a175f71baa5b24e53fcce67b4d85f270" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string841 = "e3a86bc310bc8b100658d86bc6c8541de89bdf340651ecc848d1aeb29bd27695" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string842 = "e46777e5f1ac1652db3ce72dd0a2475ea515b37a737fffd743126772525a47e6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string843 = "e497cb13af9ca67fe13e37a81dc416d7cff819402aa46a7232c088e06dc74f92" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string844 = "e4d3d57f4de0497d24095cbd83d5500268323e247e4de2e69cd704975b134678" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string845 = "e51e4cf322780a163acaa6e3f0b2e04a69f071a2295231b8f4fe07e6977acf24" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string846 = "e62b8454cfe35f36330c83adb4665982afe6a22d9edd47a923a7aecf135cd99b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string847 = "e65f36c9186c0a94d3cb013a1083ef0cef93b3cbc2d8af77dc0911bcced37c62" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string848 = "e6da23f77e5990f4692c09e10a16f594a6c51b817bf14f5a7a96d3f109df5a2a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string849 = "e74ae54ecb8e0faeb06dc7f1a78bbdaf9facc8540b8b6ee404061fadad0da2de" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string850 = "e789ae7e1cf64b173de4ab20baed15152b937231db44bab8482f68f08b02a000" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string851 = "e7968efd71cb275ba11fb0bad1567611afe86181401a4c05d35516c76c5e3ca4" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string852 = "e7eeba3b5fef6c4fb2bf4aa664ce87f13d5b15f288d4c1471c5c872d67ae87d8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string853 = "e8187f2863d067a0f07cec1d4c0b7150c1975334addfc58d3c742e7bd66f4a13" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string854 = "e8f8b9e708015321f0a7be88076f0e92c7215d2d93765349c34cfe599d135b6c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string855 = "e91d6dca160c284f21b663cac5aae2f4afd9ce45e8abacb517fa34fc42e754a1" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string856 = "e92d814a584ef1960b96cd7483babd6e74a49563ee2b55955ee5fed98687993a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string857 = "e9b70f3a69ae5f1891a1f9b1b93aeb6745d632786e75bc111bc4c6b0ba201f58" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string858 = "ea080f879bb8b915bc671813077aed9e350b286df348dfc5a84429a816fc8b96" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string859 = "ea20980ea983bf6033a3c2e1a1e1b17a3915867e9e6ed44beae3bbae70bc5cd4" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string860 = "ea5653d977893407bd10f7c727996a317c378b02422e7c6d8f44e8959ad8ceb4" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string861 = "ea743427978d01e07b5aa14268ccc59fde773633a70747659af1a80da4ed0e02" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string862 = "ea96ffffce62cf41ea2478b40db5e9d23f850f983cd8dcd8b752baea0478c443" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string863 = "eae0886d4156fbf4b7af942fc3e5569d7ef36147c025d06fe30a34b852b4dcfc" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string864 = "eb0beca1758174ab255d6a183dc645005249a70c3c77db9e9eb2b24551f21114" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string865 = "ebe4b211d5a78a04727f24438102b25abc60f10ac6f222a05fbdaf119c23707e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string866 = "ec19621c142ea507d319f064c4dc19ffa3026c4e084920f0486e13a34d877d8b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string867 = "ec31a1b9d3b5672137349a35719e2f595394a90f3978d60ef5ffe7900763ac00" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string868 = "ec37a2d841bd68da48bf8743a40bd25049ce081bfff67802900163b4b8f8f84c" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string869 = "ed05f1f81000737f45d7e490a10f3b8c36b0cf898b51fe1966ce63f034e8ffcf" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string870 = "ed47878048a7624cdd5a73042c9bde820aa0befbb1908c3f2e4a1cbe5aad359f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string871 = "ed49a8c71ef4b0d5e362b0c4466f4c3cce1a8d2f641b6b994f949a144df30b76" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string872 = "ed985694d5443f8df91836bf904b8ef8c360edbbda34b6cc50d454edcf1197b3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string873 = "ee7eb509d6e06bd0c51c1d0bf2a03bde2c167fb002dd6d7a842ba209f742e90e" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string874 = "eee4a896d177f5b562ac78c7e655429a1da46fb00307d9100f63d771c32297f2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string875 = "ef3a5ae6f4d510f340b4b9bce3a7aa502ffeadbf09f37dacb0c8bf00a49d36d0" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string876 = "ef573db5da42f05fee1e9ecc1d8c53690293d2053127978a092172fa9ce864f3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string877 = "efc8c949a728d819ac20e7f03b2ceb9924a51b10130de46424a27d4bbf242b9a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string878 = "efd24e7507ef6865e7f04947fd3a18903fa8368355569ec32376d921ba2c1934" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string879 = "f0aad423001bc47bc3b1242f8cef69109262c413f151d5cf212cdd2dc341ceb3" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string880 = "f1802e0de6eea66fde52537a15d0a2972d53b74e5a2cb016f6722daec68c97ba" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string881 = "f1e7f37e2e04dc87b374beae26496df2fa80cbce527ae6276c387b82e725d021" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string882 = "f3bfcbc52736f637b0bc239e31343cd8f33f6e51ea449799e69b4225df15e325" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string883 = "f42662aa9fb2d7cb0c9a73d21efff24dbe1051497795776c9a37f47f978fc57f" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string884 = "f42adcec359a40b1ab437ac635977f99e81848c453abc16f0d015c3d62cff7f6" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string885 = "f44025a2d9ed6c009219a7e8f00e28b00bb2494c4aafc7def798957073ffd1b7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string886 = "f4d29fdb47bdeb934a39cbc50f5ef589a10f08fe345b76711695f8d49ac1d627" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string887 = "f54d129e29fabcb7328aac406ea5a08ba38df3fa327a5ecddff0de316a95b5c9" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string888 = "f5b82c817528c03e5b0e21c61b07cfba0bb80b9b7e86e12af5b39a2c47e708f7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string889 = "f61d22d8e8130ff6be2aaf36e1ac8103af3b375549d453deddedb19606751190" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string890 = "f6a47b25b4d9fa389de6360c9527c638a65bd2ee3c45d0f8b2b67afabf039f72" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string891 = "f6c0d79de6c79b74f249d3f3ee8d5066459e94e254723022b63c2a53a82b2e81" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string892 = "f8751474732f13b4139d18f33929a7fa88ca7b255455b2fb814fbc1d61ad8a6a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string893 = "f957ae5d8b980b8063af938aa7a1c1ab7293f3d63b49559a82fc3da0c651ea88" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string894 = "f993560f69c40d4e80da65ac4db6b38e12e439230979336148abd479f091f8a8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string895 = "f99e70dc19c3d3b3aeeefb1f8dd6b4a2e75d3195f87a7461cd26de4041629f35" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string896 = "f9b67e1fce905f904c0516ff91e93d776e788f1bd0ac5a10c384b65d217f0c79" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string897 = "fa1fa604b788cc583542e6ea92a9a7802efc55422c9bc18ddadc04d8b5683329" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string898 = "fa3de04b165bd518b476d23212d3b7ed1b92a600acba4f01ec35213f0efe1467" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string899 = "fa8addfe13555c20633386fe8c9ceda53336fada732d984c214632ebb73063f2" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string900 = "fa8ea8f183235df6d194ee66f9289be6e5020000d9eea029a3788da393db3b4a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string901 = "fb949f56cdf4e529d69565be537d248f369f54f4fcceeff2f04a82e9f778bc36" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string902 = "fb9a347d266e2e75fc1dd9f66e2bbb661069771458a8638c8c4c7a114bb52f05" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string903 = "fba90278c07ff36e8f4958fbe66bad409a65639acebbba7297f53ced7283a369" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string904 = "fbc6438df3960d925a5d2d4880ce806ac26a73a063c66e3804ff7de9046b354b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string905 = "fbd0e54fedad58bf67971c40fcf7326684a2ec8c882cb14b27ac0ffb9a1fa60b" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string906 = "fc3b2d828651918334e05b57bf4f3c0990d545ac90c9aa062bf0042d70c2d55a" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string907 = "fc5559338c0ade4db54d8d511db5fe0962340177667dcacc071dcdcb956312f4" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string908 = "fcba85845f29fb731817fc013242bc410b18ea1e1cb3ff4ba52b599043f4e2d7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string909 = "fda01773787fa74e66a7ecb944653dddd36fc7b298ff32ebbb06ab2099df4478" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string910 = "fe3714ffa85da624ca247913dfe99fb303ba4217a6e95bc63bf6823874f40b49" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string911 = "fe8fcb5a9335c55ef7fc6c7493e9ee1b13545c194d7ee3bdbb4a9dc943592cd7" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string912 = "ff097fb7664b07349f132f53d87df71a68d8ab6b74af21f8a3691024f57671f8" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string913 = "ff54582037d9e221decb7c000425ee66f79551184793fd78caa946e66d6b94f5" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string914 = "ff54f9ababc26c1c7acdbf9e133e48bc60860371ae8f36997d6a345a1db539e1" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string915 = /find\s\.\s\-type\sf\s\-name\s\.bash_history/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string916 = /find\s\.\s\-type\sf\s\-name\s\.fetchmailrc/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string917 = /find\s\.\s\-type\sf\s\-name\s\.htpasswd/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string918 = /find\s\.\s\-type\sf\s\-name\sservice\.pwd/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string919 = /find\s\.\s\-type\sf\s\-perm\s\-02000\s\-ls/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string920 = /find\s\.\s\-type\sf\s\-perm\s\-04000\s\-ls/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string921 = /find\s\/\s\-type\sf\s\-name\s\.bash_history/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string922 = /find\s\/\s\-type\sf\s\-name\s\.fetchmailrc/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string923 = /find\s\/\s\-type\sf\s\-name\s\.htpasswd/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string924 = /find\s\/\s\-type\sf\s\-name\sconfig\.inc\.php/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string925 = /find\s\/\s\-type\sf\s\-name\sservice\.pwd/
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string926 = "find / -type f -perm -02000 -ls"
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string927 = "find / -type f -perm -04000 -ls"
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string928 = /FromBase64String\(\\"UmVxdWVzdC5JdGVtWyJ6Il0\=\\"/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string929 = "function HTTP-Backdoor-Logic" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string930 = "function Persistence_HTTP" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string931 = /Get\-Information_exfil\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string932 = "Get-LsaSecret " nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string933 = /Get\-LSASecret\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string934 = /HTTP\-Backdoor\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string935 = "Invoke-Medusa " nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string936 = "Invoke-NinjaCopy" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string937 = "Invoke-PingSweep " nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string938 = /K07MLUosSSzOyM\+OycvMzsjM4eUCAA\=\=/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string939 = /Keylogger\.ps1/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string940 = /Led\-Zeppelin\\\'s\sLFI\sFile\sdumper/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string941 = "net localg\"\"&pgh&\"\"roup " nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string942 = /net\slocalg\\"\\"\+ezyq\+\\"\\"roup\s/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string943 = /net\su\\"\\"\+rmct\+\\"\\"ser\s/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string944 = "net us\"\"&skj&\"\"er " nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string945 = "net user b4che10r " nocase ascii wide
        // Description: A collection of webshell
        // Reference: https://github.com/Peaky-XD/webshell
        $string946 = "Peaky-XD/webshell" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string947 = /Php\sBackdoor\sv\s1\.0\sby\s\^Jerem/ nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string948 = "w00tw00tw00t" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string949 = "Win phpMyAdmin Hacked" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string950 = "You have been hack By Shany with Love To #worst" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string951 = "YOUR SERVER HAS BEED HACKED " nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string952 = "zSI9xSN3Ob0gBCYaOnwey7whAH4kwX0gBCYa" nocase ascii wide
        // Description: collection of webshell - observed used by famous webshells
        // Reference: https://github.com/tennc/webshell
        $string953 = "zSI9xWleO7AbADEmAD0kxX4fACJezmMeyt==" nocase ascii wide
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
