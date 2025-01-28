rule SSH_Snake
{
    meta:
        description = "Detection patterns for the tool 'SSH-Snake' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SSH-Snake"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string1 = /\sSnake\.sh\s/
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string2 = /\sSnake\.sh/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string3 = /\/badcert\.pem/
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string4 = /\/badkey\.pem/
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string5 = /\/Snake\.nocomments\.sh/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string6 = /\/Snake\.sh/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string7 = /\/SSH\-Snake\.git/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string8 = "/SSH-Snake/" nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string9 = /\[\!\]\sInvalid\ssandbox\sevasion\stechnique\sprovided\!/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string10 = /\[\+\]\sDirect\ssyscalls\shave\sbeen\sdisabled\,\sgetting\sAPI\sfuncs\sfrom\sntdll\sin\smemory\!/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string11 = /\[\+\]\sInjecting\sinto\sexisting\sprocess/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string12 = /\[\+\]\sNTDLL\sunhooking\senabled/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string13 = /\[\+\]\sPPID\sSpoofing\shas\sbeen\sdisabled/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string14 = /\[\+\]\sSysWhispers\sis\snot\scompatible\swith\sObfuscator\-LLVM\;\sswitching\sto\sGetSyscallStub/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string15 = /\[\+\]\sUsing\sDLL\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string16 = /\[\+\]\sUsing\sdomain\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string17 = /\[\+\]\sUsing\shostname\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string18 = /\[\+\]\sUsing\sObfuscator\-LLVM\sto\scompile\sstub\.\.\./ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string19 = /\[\+\]\sUsing\ssleep\stechnique\sfor\ssandbox\sevasion/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string20 = /\[\+\]\sUsing\sSysWhispers2\sfor\ssyscalls/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string21 = /\[\+\]\sUsing\sSysWhispers3\sfor\ssyscalls/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string22 = /\[\+\]\sUsing\susername\senumeration\sfor\ssandbox\sevasion/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string23 = /\[\+\]\sValid\sshellcode\sexecution\smethods\sare\:\sPoolPartyModuleStomping/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string24 = "MegaManSec/SSH-Snake" nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string25 = /Shellcode\spath\schanged\:.{0,100}shellcode_path/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string26 = /SSHSnake\.log/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string27 = "SSH-Snake-main" nocase ascii wide
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
