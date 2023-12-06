rule mimikatz
{
    meta:
        description = "Detection patterns for the tool 'mimikatz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mimikatz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: mimikatz default strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string1 = /\sBenjamin\sDELPY\s/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string2 = /\'\sp::d\s\'/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string3 = /\'\ss::l\s\'/ nocase ascii wide
        // Description: removing process protection for the lsass.exe process can potentially enable adversaries to inject malicious code or manipulate the process to escalate privileges or gather sensitive information such as credentials. command: !processprotect /process:lsass.exe /remove
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string4 = /\!processprotect\s.{0,1000}lsass\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string5 = /\.kirbi\s/ nocase ascii wide
        // Description: Mimikatz Using domain trust key From the DC dump the hash of the currentdomain\targetdomain$ trust account using Mimikatz (e.g. with LSADump or DCSync). Then using this trust key and the domain SIDs. forge an inter-realm TGT using Mimikatz adding the SID for the target domains enterprise admins group to our SID history.
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string6 = /\/domain:.{0,1000}\s\/sid:.{0,1000}\s\/sids:.{0,1000}\s\/rc4:.{0,1000}\s\/user:.{0,1000}\s\/service:krbtgt\s\/target:.{0,1000}\.kirbi/ nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 script argument
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string7 = /\/DumpCerts/ nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 script argument
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string8 = /\/DumpCreds/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/vyrus001/go-mimikatz
        $string9 = /\/go\-mimikatz/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string10 = /\/kiwi_passwords\.yar/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string11 = /\/mimi32\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string12 = /\/mimi64\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string13 = /\/mimicom\.idl/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string14 = /\/mimidrv\.sys/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string15 = /\/mimidrv\.zip/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string16 = /\/mimikatz\.sln/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string17 = /\/mimikatz_bypass\/mimikatz\.py/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string18 = /\/mimikatz_bypass\/mimikatz2\.py/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string19 = /\/mimikatz_bypassAV\/main\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string20 = /\/mimikatz_bypassAV\/mimikatz_load\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string21 = /\/mimikatz_load\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string22 = /\/mimilib\.def/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string23 = /\/mimilove\.c/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string24 = /\/mimilove\.h/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string25 = /\/mimilove\.rc/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/skelsec/pypykatz
        $string26 = /\/pypykatz\.py/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string27 = /\/rakjong\/mimikatz_bypassAV\// nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/skelsec/pypykatz
        $string28 = /\/skelsec\/pypykatz/ nocase ascii wide
        // Description: mimikatz powershell alternative name
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string29 = /\\katz\.ps1/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string30 = /\\mimi32\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string31 = /\\mimi64\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string32 = /\<3\seo\.oe/ nocase ascii wide
        // Description: mimikatz default strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string33 = /A\sLa\sVie.{0,1000}\sA\sL\'Amour/ nocase ascii wide
        // Description: mimikatz default strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string34 = /benjamin\@gentilkiwi\.com/ nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string35 = /chocolate\.kirbi/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string36 = /Copyright\s\(c\)\s2007\s\-\s2021\sgentilkiwi\s\(Benjamin\sDELPY\)/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string37 = /crypto::capi/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string38 = /crypto::certificates/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string39 = /crypto::certtohw/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string40 = /crypto::cng/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string41 = /crypto::extract/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string42 = /crypto::hash/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string43 = /crypto::keys/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string44 = /crypto::providers/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string45 = /crypto::sc/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string46 = /crypto::scauth/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string47 = /crypto::stores/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string48 = /crypto::system/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string49 = /crypto::tpminfo/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string50 = /dpapi::blob/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string51 = /dpapi::cache/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string52 = /dpapi::capi/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string53 = /dpapi::chrome/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string54 = /dpapi::cloudapkd/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string55 = /dpapi::cloudapreg/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string56 = /dpapi::cng/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string57 = /dpapi::create/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string58 = /dpapi::cred/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string59 = /dpapi::credhist/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string60 = /dpapi::luna/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string61 = /dpapi::masterkey/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string62 = /dpapi::protect/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string63 = /dpapi::ps/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string64 = /dpapi::rdg/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string65 = /dpapi::sccm/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string66 = /dpapi::ssh/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string67 = /dpapi::tpm/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string68 = /dpapi::vault/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string69 = /dpapi::wifi/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string70 = /dpapi::wwman/ nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 script argument
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string71 = /\-DumpCreds/ nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 function name
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string72 = /Enable\-SeDebugPrivilege/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string73 = /eo\.oe\.kiwi/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string74 = /event::clear/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string75 = /event::drop/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string76 = /gentilkiwi\s\(Benjamin\sDELPY\)/ nocase ascii wide
        // Description: author of mimikatz and multiple other windows exploitation tools
        // Reference: https://github.com/gentilkiwi/
        $string77 = /gentilkiwi/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string78 = /Hello\sfrom\sDCShadow/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string79 = /id::modify/ nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 function name
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string80 = /Import\-DllInRemoteProcess/ nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 function name
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string81 = /Invoke\-CreateRemoteThread/ nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 function name
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string82 = /Invoke\-Mimikatz/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/g4uss47/Invoke-Mimikatz
        $string83 = /Invoke\-Mimikatz/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/g4uss47/Invoke-Mimikatz
        $string84 = /Invoke\-Mimikatz\.ps1/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/g4uss47/Invoke-Mimikatz
        $string85 = /Invoke\-UpdateMimikatzScript\.ps1/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string86 = /kerberos::ask/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string87 = /kerberos::clist/ nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string88 = /kerberos::golden/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string89 = /kerberos::golden/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string90 = /kerberos::hash/ nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string91 = /kerberos::list/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. This function lists all Kerberos tickets in memory
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string92 = /kerberos::list/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string93 = /kerberos::ptc/ nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string94 = /kerberos::ptt/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string95 = /kerberos::ptt/ nocase ascii wide
        // Description: Mimikatz Unconstrained delegation. With administrative privileges on a server with Unconstrained Delegation set we can dump the TGTs for other users that have a connection. If we do this successfully. we can impersonate the victim user towards any service in the domain.
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string96 = /kerberos::ptt.{0,1000}\.kirbi/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string97 = /kerberos::purge/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string98 = /kerberos::tgt/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string99 = /Kiwi\sLegit\sPrinter/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string100 = /kuhl_m_sekurlsa_nt6\.c/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string101 = /kuhl_m_sekurlsa_nt6\.h/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string102 = /kuhl_m_sekurlsa_packages\.c/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string103 = /kuhl_m_sekurlsa_packages\.h/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string104 = /kuhl_m_sekurlsa_utils\.c/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string105 = /kuhl_m_sekurlsa_utils\.h/ nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string106 = /lsadump::/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string107 = /lsadump::backupkeys/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string108 = /lsadump::cache/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string109 = /lsadump::changentlm/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string110 = /lsadump::dcshadow/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string111 = /lsadump::dcsync/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string112 = /lsadump::lsa/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string113 = /lsadump::mbc/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string114 = /lsadump::netsync/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string115 = /lsadump::packages/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string116 = /lsadump::postzerologon/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string117 = /lsadump::RpData/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string118 = /lsadump::sam/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string119 = /lsadump::secrets/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string120 = /lsadump::setntlm/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string121 = /lsadump::trust/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string122 = /lsadump::zerologon/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string123 = /mimi32\.exe\s/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string124 = /mimi64\.exe\s/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string125 = /mimidrv\s\(mimikatz\)/ nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string126 = /mimidrv/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string127 = /mimidrv\.pdb/ nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string128 = /mimidrv\.sys/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string129 = /mimidrv\.sys/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string130 = /mimidrv\.sys/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string131 = /mimidrv\.zip/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string132 = /mimikatz\sfor\sWindows/ nocase ascii wide
        // Description: Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets.
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string133 = /Mimikatz/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string134 = /mimikatz\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string135 = /mimikatz_trunk/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string136 = /mimilib\s\(mimikatz\)/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string137 = /mimilib\sfor\sWindows\s\(mimikatz\)/ nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string138 = /mimilib/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string139 = /mimilib\.dll/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string140 = /mimilib\.dll/ nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string141 = /mimilove/ nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string142 = /mimilove\.exe/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string143 = /mimilove\.vcxproj/ nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string144 = /mimispool\.dll/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string145 = /misc::aadcookie/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string146 = /misc::clip/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string147 = /misc::cmd/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string148 = /misc::compress/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string149 = /misc::detours/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string150 = /misc::efs/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string151 = /misc::lock/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string152 = /misc::memssp/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string153 = /misc::mflt/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string154 = /misc::ncroutemon/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string155 = /misc::ngcsign/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string156 = /misc::printnightmare/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string157 = /misc::regedit/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string158 = /misc::sccm/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string159 = /misc::shadowcopies/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string160 = /misc::skeleton/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string161 = /misc::spooler/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string162 = /misc::taskmgr/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string163 = /misc::wp/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string164 = /misc::xor/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string165 = /net::alias/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string166 = /net::deleg/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string167 = /net::group/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string168 = /net::if/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string169 = /net::serverinfo/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string170 = /net::session/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string171 = /net::share/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string172 = /net::stats/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string173 = /net::tod/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string174 = /net::trust/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string175 = /net::user/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string176 = /net::wsession/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/Stealthbits/poshkatz
        $string177 = /poshkatz\.psd1/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string178 = /privilege::backup/ nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string179 = /privilege::debug/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string180 = /privilege::debug/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string181 = /privilege::driver/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string182 = /privilege::id/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string183 = /privilege::name/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string184 = /privilege::restore/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string185 = /privilege::security/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string186 = /privilege::sysenv/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string187 = /privilege::tcb/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string188 = /process::exports/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string189 = /process::imports/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string190 = /process::list/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string191 = /process::resume/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string192 = /process::run/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string193 = /process::runp/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string194 = /process::start/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string195 = /process::stop/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string196 = /process::suspend/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/skelsec/pypykatz
        $string197 = /pypykatz\slsa\sminidump/ nocase ascii wide
        // Description: invoke mimiaktz string found used by the tool EDRaser 
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string198 = /QWRkLU1lbWJlciBOb3RlUHJvcGVydHkgLU5hbWUgVmlydHVhbFByb3RlY3QgLVZhbHVlICRWaXJ0dWFsUHJvdGVjdA/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string199 = /rpc::close/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string200 = /rpc::connect/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string201 = /rpc::enum/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string202 = /rpc::server/ nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string203 = /sekurlsa\s/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string204 = /sekurlsa::backupkeys/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string205 = /sekurlsa::bootkey/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string206 = /sekurlsa::cloudap/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string207 = /sekurlsa::credman/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string208 = /sekurlsa::dpapi/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string209 = /sekurlsa::dpapisystem/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. This function dumps DPAPI backup keys for users who have logged on to the system
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string210 = /sekurlsa::ekeys/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string211 = /sekurlsa::kerberos/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string212 = /sekurlsa::krbtgt/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string213 = /sekurlsa::livessp/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. This function retrieves plaintext credentials from the LSA secrets in memory.
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string214 = /sekurlsa::logonpasswords/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string215 = /sekurlsa::minidump/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string216 = /sekurlsa::msv/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string217 = /sekurlsa::process/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash.This function performs pass-the-hash attacks allowing an attacker to authenticate to a remote system with a stolen hash.
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string218 = /sekurlsa::pth/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string219 = /sekurlsa::ssp/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string220 = /sekurlsa::tickets/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string221 = /sekurlsa::trust/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string222 = /sekurlsa::tspkg/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string223 = /sekurlsa::wdigest/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string224 = /service::me/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string225 = /service::preshutdown/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string226 = /service::remove/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string227 = /service::resume/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string228 = /service::shutdown/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string229 = /service::start/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string230 = /service::stop/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string231 = /service::suspend/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string232 = /sid::add/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string233 = /sid::clear/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string234 = /sid::lookup/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string235 = /sid::modify/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string236 = /sid::patch/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string237 = /sid::query/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string238 = /standard::answer/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string239 = /standard::base64/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string240 = /standard::cd/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string241 = /standard::cls/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string242 = /standard::coffee/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string243 = /standard::exit/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string244 = /standard::hostname/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string245 = /standard::localtime/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string246 = /standard::log/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string247 = /standard::sleep/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string248 = /standard::version/ nocase ascii wide
        // Description: Mimikatz Unconstrained delegation. With administrative privileges on a server with Unconstrained Delegation set we can dump the TGTs for other users that have a connection. If we do this successfully. we can impersonate the victim user towards any service in the domain.
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string249 = /ticket\.kirbi/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string250 = /token::elevate/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string251 = /token::list/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string252 = /token::revert/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string253 = /token::run/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string254 = /token::whoami/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string255 = /ts::logonpasswords/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string256 = /ts::mstsc/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string257 = /ts::multirdp/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string258 = /ts::remote/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string259 = /ts::sessions/ nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string260 = /vault::/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string261 = /vault::cred/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string262 = /vault::list/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string263 = /vincent\.letoux\@gmail\.com/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/vyrus001/go-mimikatz
        $string264 = /vyrus001\/go\-mimikatz/ nocase ascii wide
        // Description: mimikatz exploitation default password
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string265 = /waza1234/ nocase ascii wide

    condition:
        any of them
}
