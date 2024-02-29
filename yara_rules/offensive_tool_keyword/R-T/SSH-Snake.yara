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
        $string1 = /\sSnake\.sh\s/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string2 = /\sSnake\.sh/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string3 = /\/badcert\.pem/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string4 = /\/badkey\.pem/ nocase ascii wide
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
        $string8 = /\/SSH\-Snake\// nocase ascii wide
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
        $string24 = /MegaManSec\/SSH\-Snake/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string25 = /Shellcode\spath\schanged\:.{0,1000}shellcode_path/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string26 = /SSHSnake\.log/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string27 = /SSH\-Snake\-main/ nocase ascii wide

    condition:
        any of them
}
