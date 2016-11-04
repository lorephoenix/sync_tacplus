# sync_tacplus
Sync LDAP(FreeIPA) users and groups into your tac_plus.conf file

Tacacs+ doesn’t support LDAP authentication by default, but it does support PAM authentication.
Let's use PAM as a proxy authentication towards our FreeIPA environment.
With this script it will build up a new tac_plus.conf file that populates our wanted LDAP groups and users.
