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
        $string1 = /\sSnake\.sh/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string2 = /\/badcert\.pem/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string3 = /\/badkey\.pem/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string4 = /\/Snake\.nocomments\.sh/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string5 = /\/Snake\.sh/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string6 = /\/SSH\-Snake\.git/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string7 = /\/SSH\-Snake\// nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string8 = /MegaManSec\/SSH\-Snake/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string9 = /SSHSnake\.log/ nocase ascii wide
        // Description: SSH-Snake is a self-propagating - self-replicating - file-less script that automates the post-exploitation task of SSH private key and host discovery
        // Reference: https://github.com/MegaManSec/SSH-Snake
        $string10 = /SSH\-Snake\-main/ nocase ascii wide

    condition:
        any of them
}
