rule mail_in_the_middle
{
    meta:
        description = "Detection patterns for the tool 'mail-in-the-middle' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mail-in-the-middle"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string1 = /\/DiscordBot\.py/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string2 = /\/forwardedemails\.txt/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string3 = /\/Maitm\/Bells\.py/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string4 = /\/tmp\/Phishing\/documentation\.pdf\.zip/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string5 = /\/var\/log\/apache2\/forensic_log\-10080\.log/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string6 = /\[\!\]\sInvalid\ssandbox\sevasion\stechnique\sprovided\!/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string7 = /\[\+\]\sDirect\ssyscalls\shave\sbeen\sdisabled\,\sgetting\sAPI\sfuncs\sfrom\sntdll\sin\smemory\!/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string8 = /\[\+\]\sInjecting\sinto\sexisting\sprocess/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string9 = /\[\+\]\sNTDLL\sunhooking\senabled/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string10 = /\[\+\]\sPPID\sSpoofing\shas\sbeen\sdisabled/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string11 = /\[\+\]\sSysWhispers\sis\snot\scompatible\swith\sObfuscator\-LLVM\;\sswitching\sto\sGetSyscallStub/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string12 = /\[\+\]\sUsing\sDLL\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string13 = /\[\+\]\sUsing\sdomain\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string14 = /\[\+\]\sUsing\shostname\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string15 = /\[\+\]\sUsing\sObfuscator\-LLVM\sto\scompile\sstub\.\.\./ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string16 = /\[\+\]\sUsing\ssleep\stechnique\sfor\ssandbox\sevasion/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string17 = /\[\+\]\sUsing\sSysWhispers2\sfor\ssyscalls/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string18 = /\[\+\]\sUsing\sSysWhispers3\sfor\ssyscalls/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string19 = /_mailinthemiddle\.log/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string20 = /change_sandbox_evasion_method\(/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string21 = /change_shellcode_exec_method\(/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string22 = /Ding\sDing\sDing\!\sEmail\sopened\!/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string23 = /docker\sbuild\s\-t\smaitm\s/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string24 = /docker\srun\s\-\-rm\s\-ti\smaitm\s\-/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string25 = /from\sDiscordBot\simport\sMitmPuppeter/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string26 = /from\sMaitm\.Maitm\s/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string27 = /LABEL\sname\=\"Maitm\"/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string28 = /logs\/maitm\.log\"/ nocase ascii wide
        // Description: This script sits in the middle between a legitimate sender of an email and the legitimate recipient of that email. This means that we (the attackers) are receiving sensitive information not originally destined to us
        // Reference: https://github.com/sensepost/mail-in-the-middle
        $string29 = /mail\-in\-the\-middle\.py/ nocase ascii wide

    condition:
        any of them
}
