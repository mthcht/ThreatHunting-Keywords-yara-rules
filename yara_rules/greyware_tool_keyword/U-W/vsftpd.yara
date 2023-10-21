rule vsftpd
{
    meta:
        description = "Detection patterns for the tool 'vsftpd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vsftpd"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string1 = /Bad\sHTTP\sverb\./ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string2 = /bug:\spid\sactive\sin\sptrace_sandbox_free/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string3 = /Connection\srefused:\stcp_wrappers\sdenial\./ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string4 = /Connection\srefused:\stoo\smany\ssessions\sfor\sthis\saddress\./ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string5 = /Could\snot\sset\sfile\smodification\stime\./ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string6 = /couldn\'t\shandle\ssandbox\sevent/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string7 = /Input\sline\stoo\slong\./ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string8 = /pasv\sand\sport\sboth\sactive/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string9 = /poor\sbuffer\saccounting\sin\sstr_netfd_alloc/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string10 = /port\sand\spasv\sboth\sactive/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string11 = /PTRACE_SETOPTIONS\sfailure/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string12 = /syscall\s.*\sout\sof\sbounds/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string13 = /syscall\snot\spermitted:/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string14 = /syscall\svalidate\sfailed:/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string15 = /Transfer\sdone\s\(but\sfailed\sto\sopen\sdirectory\)\./ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string16 = /vsf_sysutil_read_loop/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string17 = /weird\sstatus:/ nocase ascii wide

    condition:
        any of them
}