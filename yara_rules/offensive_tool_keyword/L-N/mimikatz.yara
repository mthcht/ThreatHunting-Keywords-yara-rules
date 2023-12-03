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
        $string1 = /.{0,1000}\sBenjamin\sDELPY\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string2 = /.{0,1000}\'\sp::d\s\'.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string3 = /.{0,1000}\'\ss::l\s\'.{0,1000}/ nocase ascii wide
        // Description: removing process protection for the lsass.exe process can potentially enable adversaries to inject malicious code or manipulate the process to escalate privileges or gather sensitive information such as credentials. command: !processprotect /process:lsass.exe /remove
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string4 = /.{0,1000}\!processprotect\s.{0,1000}lsass\.exe.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string5 = /.{0,1000}\.kirbi\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz Using domain trust key From the DC dump the hash of the currentdomain\targetdomain$ trust account using Mimikatz (e.g. with LSADump or DCSync). Then using this trust key and the domain SIDs. forge an inter-realm TGT using Mimikatz adding the SID for the target domains enterprise admins group to our SID history.
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string6 = /.{0,1000}\/domain:.{0,1000}\s\/sid:.{0,1000}\s\/sids:.{0,1000}\s\/rc4:.{0,1000}\s\/user:.{0,1000}\s\/service:krbtgt\s\/target:.{0,1000}\.kirbi.{0,1000}/ nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 script argument
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string7 = /.{0,1000}\/DumpCerts.{0,1000}/ nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 script argument
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string8 = /.{0,1000}\/DumpCreds.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/vyrus001/go-mimikatz
        $string9 = /.{0,1000}\/go\-mimikatz.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string10 = /.{0,1000}\/kiwi_passwords\.yar.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string11 = /.{0,1000}\/mimi32\.exe.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string12 = /.{0,1000}\/mimi64\.exe.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string13 = /.{0,1000}\/mimicom\.idl.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string14 = /.{0,1000}\/mimidrv\.sys.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string15 = /.{0,1000}\/mimidrv\.zip.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string16 = /.{0,1000}\/mimikatz\.sln.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string17 = /.{0,1000}\/mimikatz_bypass\/mimikatz\.py.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string18 = /.{0,1000}\/mimikatz_bypass\/mimikatz2\.py.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string19 = /.{0,1000}\/mimikatz_bypassAV\/main\.exe.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string20 = /.{0,1000}\/mimikatz_bypassAV\/mimikatz_load\.exe.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string21 = /.{0,1000}\/mimikatz_load\.exe.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string22 = /.{0,1000}\/mimilib\.def.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string23 = /.{0,1000}\/mimilove\.c.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string24 = /.{0,1000}\/mimilove\.h.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string25 = /.{0,1000}\/mimilove\.rc.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/skelsec/pypykatz
        $string26 = /.{0,1000}\/pypykatz\.py.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string27 = /.{0,1000}\/rakjong\/mimikatz_bypassAV\/.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/skelsec/pypykatz
        $string28 = /.{0,1000}\/skelsec\/pypykatz.{0,1000}/ nocase ascii wide
        // Description: mimikatz powershell alternative name
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string29 = /.{0,1000}\\katz\.ps1.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string30 = /.{0,1000}\\mimi32\.exe.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string31 = /.{0,1000}\\mimi64\.exe.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string32 = /.{0,1000}\<3\seo\.oe.{0,1000}/ nocase ascii wide
        // Description: mimikatz default strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string33 = /.{0,1000}A\sLa\sVie.{0,1000}\sA\sL\'Amour.{0,1000}/ nocase ascii wide
        // Description: mimikatz default strings
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string34 = /.{0,1000}benjamin\@gentilkiwi\.com.{0,1000}/ nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string35 = /.{0,1000}chocolate\.kirbi.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string36 = /.{0,1000}Copyright\s\(c\)\s2007\s\-\s2021\sgentilkiwi\s\(Benjamin\sDELPY\).{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string37 = /.{0,1000}crypto::capi.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string38 = /.{0,1000}crypto::certificates.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string39 = /.{0,1000}crypto::certtohw.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string40 = /.{0,1000}crypto::cng.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string41 = /.{0,1000}crypto::extract.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string42 = /.{0,1000}crypto::hash.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string43 = /.{0,1000}crypto::keys.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string44 = /.{0,1000}crypto::providers.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string45 = /.{0,1000}crypto::sc.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string46 = /.{0,1000}crypto::scauth.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string47 = /.{0,1000}crypto::stores.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string48 = /.{0,1000}crypto::system.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string49 = /.{0,1000}crypto::tpminfo.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string50 = /.{0,1000}dpapi::blob.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string51 = /.{0,1000}dpapi::cache.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string52 = /.{0,1000}dpapi::capi.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string53 = /.{0,1000}dpapi::chrome.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string54 = /.{0,1000}dpapi::cloudapkd.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string55 = /.{0,1000}dpapi::cloudapreg.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string56 = /.{0,1000}dpapi::cng.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string57 = /.{0,1000}dpapi::create.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string58 = /.{0,1000}dpapi::cred.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string59 = /.{0,1000}dpapi::credhist.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string60 = /.{0,1000}dpapi::luna.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string61 = /.{0,1000}dpapi::masterkey.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string62 = /.{0,1000}dpapi::protect.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string63 = /.{0,1000}dpapi::ps.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string64 = /.{0,1000}dpapi::rdg.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string65 = /.{0,1000}dpapi::sccm.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string66 = /.{0,1000}dpapi::ssh.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string67 = /.{0,1000}dpapi::tpm.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string68 = /.{0,1000}dpapi::vault.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string69 = /.{0,1000}dpapi::wifi.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string70 = /.{0,1000}dpapi::wwman.{0,1000}/ nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 script argument
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string71 = /.{0,1000}\-DumpCreds.{0,1000}/ nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 function name
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string72 = /.{0,1000}Enable\-SeDebugPrivilege.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string73 = /.{0,1000}eo\.oe\.kiwi.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string74 = /.{0,1000}event::clear.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string75 = /.{0,1000}event::drop.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string76 = /.{0,1000}gentilkiwi\s\(Benjamin\sDELPY\).{0,1000}/ nocase ascii wide
        // Description: author of mimikatz and multiple other windows exploitation tools
        // Reference: https://github.com/gentilkiwi/
        $string77 = /.{0,1000}gentilkiwi.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string78 = /.{0,1000}Hello\sfrom\sDCShadow.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string79 = /.{0,1000}id::modify.{0,1000}/ nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 function name
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string80 = /.{0,1000}Import\-DllInRemoteProcess.{0,1000}/ nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 function name
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string81 = /.{0,1000}Invoke\-CreateRemoteThread.{0,1000}/ nocase ascii wide
        // Description: Invoke-Mimikatz.ps1 function name
        // Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
        $string82 = /.{0,1000}Invoke\-Mimikatz.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/g4uss47/Invoke-Mimikatz
        $string83 = /.{0,1000}Invoke\-Mimikatz.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/g4uss47/Invoke-Mimikatz
        $string84 = /.{0,1000}Invoke\-Mimikatz\.ps1.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/g4uss47/Invoke-Mimikatz
        $string85 = /.{0,1000}Invoke\-UpdateMimikatzScript\.ps1.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string86 = /.{0,1000}kerberos::ask.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string87 = /.{0,1000}kerberos::clist.{0,1000}/ nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string88 = /.{0,1000}kerberos::golden.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string89 = /.{0,1000}kerberos::golden.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string90 = /.{0,1000}kerberos::hash.{0,1000}/ nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string91 = /.{0,1000}kerberos::list.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. This function lists all Kerberos tickets in memory
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string92 = /.{0,1000}kerberos::list.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string93 = /.{0,1000}kerberos::ptc.{0,1000}/ nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string94 = /.{0,1000}kerberos::ptt.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string95 = /.{0,1000}kerberos::ptt.{0,1000}/ nocase ascii wide
        // Description: Mimikatz Unconstrained delegation. With administrative privileges on a server with Unconstrained Delegation set we can dump the TGTs for other users that have a connection. If we do this successfully. we can impersonate the victim user towards any service in the domain.
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string96 = /.{0,1000}kerberos::ptt.{0,1000}\.kirbi.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string97 = /.{0,1000}kerberos::purge.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string98 = /.{0,1000}kerberos::tgt.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string99 = /.{0,1000}Kiwi\sLegit\sPrinter.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string100 = /.{0,1000}kuhl_m_sekurlsa_nt6\.c.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string101 = /.{0,1000}kuhl_m_sekurlsa_nt6\.h.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string102 = /.{0,1000}kuhl_m_sekurlsa_packages\.c.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string103 = /.{0,1000}kuhl_m_sekurlsa_packages\.h.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string104 = /.{0,1000}kuhl_m_sekurlsa_utils\.c.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string105 = /.{0,1000}kuhl_m_sekurlsa_utils\.h.{0,1000}/ nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string106 = /.{0,1000}lsadump::.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string107 = /.{0,1000}lsadump::backupkeys.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string108 = /.{0,1000}lsadump::cache.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string109 = /.{0,1000}lsadump::changentlm.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string110 = /.{0,1000}lsadump::dcshadow.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string111 = /.{0,1000}lsadump::dcsync.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string112 = /.{0,1000}lsadump::lsa.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string113 = /.{0,1000}lsadump::mbc.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string114 = /.{0,1000}lsadump::netsync.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string115 = /.{0,1000}lsadump::packages.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string116 = /.{0,1000}lsadump::postzerologon.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string117 = /.{0,1000}lsadump::RpData.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string118 = /.{0,1000}lsadump::sam.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string119 = /.{0,1000}lsadump::secrets.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string120 = /.{0,1000}lsadump::setntlm.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string121 = /.{0,1000}lsadump::trust.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string122 = /.{0,1000}lsadump::zerologon.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string123 = /.{0,1000}mimi32\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string124 = /.{0,1000}mimi64\.exe\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string125 = /.{0,1000}mimidrv\s\(mimikatz\).{0,1000}/ nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string126 = /.{0,1000}mimidrv.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string127 = /.{0,1000}mimidrv\.pdb.{0,1000}/ nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string128 = /.{0,1000}mimidrv\.sys.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string129 = /.{0,1000}mimidrv\.sys.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string130 = /.{0,1000}mimidrv\.sys.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string131 = /.{0,1000}mimidrv\.zip.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string132 = /.{0,1000}mimikatz\sfor\sWindows.{0,1000}/ nocase ascii wide
        // Description: Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets.
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string133 = /.{0,1000}Mimikatz.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string134 = /.{0,1000}mimikatz\.exe.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string135 = /.{0,1000}mimikatz_trunk.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string136 = /.{0,1000}mimilib\s\(mimikatz\).{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string137 = /.{0,1000}mimilib\sfor\sWindows\s\(mimikatz\).{0,1000}/ nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string138 = /.{0,1000}mimilib.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string139 = /.{0,1000}mimilib\.dll.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string140 = /.{0,1000}mimilib\.dll.{0,1000}/ nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string141 = /.{0,1000}mimilove.{0,1000}/ nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string142 = /.{0,1000}mimilove\.exe.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string143 = /.{0,1000}mimilove\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: mimikatz exploitation 
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string144 = /.{0,1000}mimispool\.dll.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string145 = /.{0,1000}misc::aadcookie.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string146 = /.{0,1000}misc::clip.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string147 = /.{0,1000}misc::cmd.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string148 = /.{0,1000}misc::compress.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string149 = /.{0,1000}misc::detours.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string150 = /.{0,1000}misc::efs.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string151 = /.{0,1000}misc::lock.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string152 = /.{0,1000}misc::memssp.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string153 = /.{0,1000}misc::mflt.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string154 = /.{0,1000}misc::ncroutemon.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string155 = /.{0,1000}misc::ngcsign.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string156 = /.{0,1000}misc::printnightmare.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string157 = /.{0,1000}misc::regedit.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string158 = /.{0,1000}misc::sccm.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string159 = /.{0,1000}misc::shadowcopies.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string160 = /.{0,1000}misc::skeleton.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string161 = /.{0,1000}misc::spooler.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string162 = /.{0,1000}misc::taskmgr.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string163 = /.{0,1000}misc::wp.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string164 = /.{0,1000}misc::xor.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string165 = /.{0,1000}net::alias.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string166 = /.{0,1000}net::deleg.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string167 = /.{0,1000}net::group.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string168 = /.{0,1000}net::if.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string169 = /.{0,1000}net::serverinfo.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string170 = /.{0,1000}net::session.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string171 = /.{0,1000}net::share.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string172 = /.{0,1000}net::stats.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string173 = /.{0,1000}net::tod.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string174 = /.{0,1000}net::trust.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string175 = /.{0,1000}net::user.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string176 = /.{0,1000}net::wsession.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/Stealthbits/poshkatz
        $string177 = /.{0,1000}poshkatz\.psd1.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string178 = /.{0,1000}privilege::backup.{0,1000}/ nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string179 = /.{0,1000}privilege::debug.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string180 = /.{0,1000}privilege::debug.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string181 = /.{0,1000}privilege::driver.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string182 = /.{0,1000}privilege::id.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string183 = /.{0,1000}privilege::name.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string184 = /.{0,1000}privilege::restore.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string185 = /.{0,1000}privilege::security.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string186 = /.{0,1000}privilege::sysenv.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string187 = /.{0,1000}privilege::tcb.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string188 = /.{0,1000}process::exports.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string189 = /.{0,1000}process::imports.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string190 = /.{0,1000}process::list.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string191 = /.{0,1000}process::resume.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string192 = /.{0,1000}process::run.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string193 = /.{0,1000}process::runp.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string194 = /.{0,1000}process::start.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string195 = /.{0,1000}process::stop.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string196 = /.{0,1000}process::suspend.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/skelsec/pypykatz
        $string197 = /.{0,1000}pypykatz\slsa\sminidump.{0,1000}/ nocase ascii wide
        // Description: invoke mimiaktz string found used by the tool EDRaser 
        // Reference: https://github.com/SafeBreach-Labs/EDRaser
        $string198 = /.{0,1000}QWRkLU1lbWJlciBOb3RlUHJvcGVydHkgLU5hbWUgVmlydHVhbFByb3RlY3QgLVZhbHVlICRWaXJ0dWFsUHJvdGVjdA.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string199 = /.{0,1000}rpc::close.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string200 = /.{0,1000}rpc::connect.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string201 = /.{0,1000}rpc::enum.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string202 = /.{0,1000}rpc::server.{0,1000}/ nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string203 = /.{0,1000}sekurlsa\s.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string204 = /.{0,1000}sekurlsa::backupkeys.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string205 = /.{0,1000}sekurlsa::bootkey.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string206 = /.{0,1000}sekurlsa::cloudap.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string207 = /.{0,1000}sekurlsa::credman.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string208 = /.{0,1000}sekurlsa::dpapi.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string209 = /.{0,1000}sekurlsa::dpapisystem.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. This function dumps DPAPI backup keys for users who have logged on to the system
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string210 = /.{0,1000}sekurlsa::ekeys.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string211 = /.{0,1000}sekurlsa::kerberos.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string212 = /.{0,1000}sekurlsa::krbtgt.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string213 = /.{0,1000}sekurlsa::livessp.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. This function retrieves plaintext credentials from the LSA secrets in memory.
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string214 = /.{0,1000}sekurlsa::logonpasswords.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string215 = /.{0,1000}sekurlsa::minidump.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string216 = /.{0,1000}sekurlsa::msv.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string217 = /.{0,1000}sekurlsa::process.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash.This function performs pass-the-hash attacks allowing an attacker to authenticate to a remote system with a stolen hash.
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string218 = /.{0,1000}sekurlsa::pth.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string219 = /.{0,1000}sekurlsa::ssp.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string220 = /.{0,1000}sekurlsa::tickets.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string221 = /.{0,1000}sekurlsa::trust.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string222 = /.{0,1000}sekurlsa::tspkg.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string223 = /.{0,1000}sekurlsa::wdigest.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string224 = /.{0,1000}service::me.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string225 = /.{0,1000}service::preshutdown.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string226 = /.{0,1000}service::remove.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string227 = /.{0,1000}service::resume.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string228 = /.{0,1000}service::shutdown.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string229 = /.{0,1000}service::start.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string230 = /.{0,1000}service::stop.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string231 = /.{0,1000}service::suspend.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string232 = /.{0,1000}sid::add.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string233 = /.{0,1000}sid::clear.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string234 = /.{0,1000}sid::lookup.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string235 = /.{0,1000}sid::modify.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string236 = /.{0,1000}sid::patch.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string237 = /.{0,1000}sid::query.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string238 = /.{0,1000}standard::answer.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string239 = /.{0,1000}standard::base64.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string240 = /.{0,1000}standard::cd.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string241 = /.{0,1000}standard::cls.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string242 = /.{0,1000}standard::coffee.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string243 = /.{0,1000}standard::exit.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string244 = /.{0,1000}standard::hostname.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string245 = /.{0,1000}standard::localtime.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string246 = /.{0,1000}standard::log.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string247 = /.{0,1000}standard::sleep.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string248 = /.{0,1000}standard::version.{0,1000}/ nocase ascii wide
        // Description: Mimikatz Unconstrained delegation. With administrative privileges on a server with Unconstrained Delegation set we can dump the TGTs for other users that have a connection. If we do this successfully. we can impersonate the victim user towards any service in the domain.
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string249 = /.{0,1000}ticket\.kirbi.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string250 = /.{0,1000}token::elevate.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string251 = /.{0,1000}token::list.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string252 = /.{0,1000}token::revert.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string253 = /.{0,1000}token::run.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string254 = /.{0,1000}token::whoami.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string255 = /.{0,1000}ts::logonpasswords.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string256 = /.{0,1000}ts::mstsc.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string257 = /.{0,1000}ts::multirdp.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string258 = /.{0,1000}ts::remote.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string259 = /.{0,1000}ts::sessions.{0,1000}/ nocase ascii wide
        // Description: mimikatz exploitation command
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string260 = /.{0,1000}vault::.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string261 = /.{0,1000}vault::cred.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets. keyword taken from hayabusa-rules win_alert_mimikatz_keywords.yml
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string262 = /.{0,1000}vault::list.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string263 = /.{0,1000}vincent\.letoux\@gmail\.com.{0,1000}/ nocase ascii wide
        // Description: Mimikatz keywords and commands Well known to extract plaintexts passwords. hash. PIN code and kerberos tickets from memory. mimikatz can also perform pass-the-hash. pass-the-ticket or build Golden tickets
        // Reference: https://github.com/vyrus001/go-mimikatz
        $string264 = /.{0,1000}vyrus001\/go\-mimikatz.{0,1000}/ nocase ascii wide
        // Description: mimikatz exploitation default password
        // Reference: https://github.com/gentilkiwi/mimikatz
        $string265 = /.{0,1000}waza1234.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
