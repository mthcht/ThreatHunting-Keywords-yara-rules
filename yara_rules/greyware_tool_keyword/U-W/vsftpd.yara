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
        $string1 = /.{0,1000}Bad\sHTTP\sverb\..{0,1000}/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string2 = /.{0,1000}bug:\spid\sactive\sin\sptrace_sandbox_free.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string3 = /.{0,1000}Connection\srefused:\stcp_wrappers\sdenial\..{0,1000}/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string4 = /.{0,1000}Connection\srefused:\stoo\smany\ssessions\sfor\sthis\saddress\..{0,1000}/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string5 = /.{0,1000}Could\snot\sset\sfile\smodification\stime\..{0,1000}/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string6 = /.{0,1000}couldn\'t\shandle\ssandbox\sevent.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string7 = /.{0,1000}Input\sline\stoo\slong\..{0,1000}/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string8 = /.{0,1000}pasv\sand\sport\sboth\sactive.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string9 = /.{0,1000}poor\sbuffer\saccounting\sin\sstr_netfd_alloc.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string10 = /.{0,1000}port\sand\spasv\sboth\sactive.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string11 = /.{0,1000}PTRACE_SETOPTIONS\sfailure.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string12 = /.{0,1000}syscall\s.{0,1000}\sout\sof\sbounds.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string13 = /.{0,1000}syscall\snot\spermitted:.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string14 = /.{0,1000}syscall\svalidate\sfailed:.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string15 = /.{0,1000}Transfer\sdone\s\(but\sfailed\sto\sopen\sdirectory\)\..{0,1000}/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string16 = /.{0,1000}vsf_sysutil_read_loop.{0,1000}/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string17 = /.{0,1000}weird\sstatus:.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
