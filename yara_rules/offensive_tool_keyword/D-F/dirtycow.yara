rule dirtycow
{
    meta:
        description = "Detection patterns for the tool 'dirtycow' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dirtycow"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Linux vulnerability name to go root CVE-2016-5195) Dirty COW est une vulnrabilit de scurit du noyau Linux qui affecte tous les systmes d'exploitation Linux. y compris Android. C'est un dfaut d'lvation de privilge qui exploite une condition de concurrence dans la mise en uvre de la copie sur criture dans le noyau de gestion de la mmoire
        // Reference: multiple pocs on github and others places 
        $string1 = /dirtycow/ nocase ascii wide

    condition:
        any of them
}
