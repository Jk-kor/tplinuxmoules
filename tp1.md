# TP Avancé : "Mission Ultime : Sauvegarde et Sécurisation"
## Contexte
``` Votre serveur critique est opérationnel, mais de nombreuses failles subsistent. Votre objectif est d'identifier les faiblesses, de sécuriser les données et d’automatiser les surveillances pour garantir un fonctionnement sûr à long terme.``` 

## Objectifs
1. Surveiller les répertoires critiques pour détecter des modifications suspectes.
2. Identifier et éliminer des tâches malveillantes laissées par des attaquants.
3. Réorganiser les données pour optimiser l’espace disque avec LVM.
4. Automatiser les sauvegardes et surveillances avec des scripts robustes.
5. Configurer un pare-feu pour protéger les services actifs.

## Étape 1 : Analyse et nettoyage du serveur
### 1.Lister les tâches cron pour détecter des backdoors :

```d
[root@vbox ~]# for user in $(cut -f1 -d: /etc/passwd); do
    echo "---- Tâches cron pour l'utilisateur : $user ----"
    crontab -u $user -l 2>/dev/null || echo "Aucune tâche cron pour $user"
done
---- Tâches cron pour l'utilisateur : root ----
Aucune tâche cron pour root
---- Tâches cron pour l'utilisateur : bin ----
Aucune tâche cron pour bin
---- Tâches cron pour l'utilisateur : daemon ----
Aucune tâche cron pour daemon
---- Tâches cron pour l'utilisateur : adm ----
Aucune tâche cron pour adm
---- Tâches cron pour l'utilisateur : lp ----
Aucune tâche cron pour lp
---- Tâches cron pour l'utilisateur : sync ----
Aucune tâche cron pour sync
---- Tâches cron pour l'utilisateur : shutdown ----
Aucune tâche cron pour shutdown
---- Tâches cron pour l'utilisateur : halt ----
Aucune tâche cron pour halt
---- Tâches cron pour l'utilisateur : mail ----
Aucune tâche cron pour mail
---- Tâches cron pour l'utilisateur : operator ----
Aucune tâche cron pour operator
---- Tâches cron pour l'utilisateur : games ----
Aucune tâche cron pour games
---- Tâches cron pour l'utilisateur : ftp ----
Aucune tâche cron pour ftp
---- Tâches cron pour l'utilisateur : nobody ----
Aucune tâche cron pour nobody
---- Tâches cron pour l'utilisateur : tss ----
Aucune tâche cron pour tss
---- Tâches cron pour l'utilisateur : systemd-coredump ----
Aucune tâche cron pour systemd-coredump
---- Tâches cron pour l'utilisateur : dbus ----
Aucune tâche cron pour dbus
---- Tâches cron pour l'utilisateur : sssd ----
Aucune tâche cron pour sssd
---- Tâches cron pour l'utilisateur : chrony ----
Aucune tâche cron pour chrony
---- Tâches cron pour l'utilisateur : sshd ----
Aucune tâche cron pour sshd
---- Tâches cron pour l'utilisateur : attacker ----
*/10 * * * * /tmp/.hidden_script
``` 


### 2. Identifier et supprimer les fichiers cachés :

```v
[root@vbox ~]# find /tmp -type f -name ".*" -ls
    33371      4 -rwxrwxrwx   1 attacker attacker       17 Nov 24 18:11 /tmp/.hidden_script
    19874      4 -rwxrwxrwx   1 attacker attacker       18 Nov 24 18:24 /tmp/.hidden_file
```

```v
[root@vbox ~]# find /var/tmp -type f -name ".*" -ls
    33380      4 -rwxrwxrwx   1 attacker attacker        7 Nov 24 20:10 /var/tmp/.nop
```
```v
[root@vbox ~]# find /home -type f -name ".*" -ls
    20767      4 -rw-r--r--   1 attacker attacker      141 Apr 30  2024 /home/attacker/.bash_profile
    20771      4 -rw-r--r--   1 attacker attacker      492 Apr 30  2024 /home/attacker/.bashrc
    20978      4 -rw-r--r--   1 attacker attacker       18 Apr 30  2024 /home/attacker/.bash_logout
    33519      4 -rw-------   1 attacker attacker        3 Nov 24 18:48 /home/attacker/.bash_history
    33425      4 -rw-r--r--   1 attacker attacker       18 Nov 24 20:09 /home/attacker/.hidden_file 
  ``` 

  ```v
[root@vbox ~]# cat /tmp/.hidden_script
cat /tmp/.hidden_file
cat /var/tmp/.nop
cat /home/attacker/.hidden_file
malicious script
malicious content
héhé
malicious content
  ```
### Supprimez tout fichier suspect ou inconnu.
```v
[root@vbox ~]# rm -f /tmp/.hidden_script /tmp/.hidden_file /var/tmp/.nop /home/attacker/.hidden_file
vvv

```v
[root@vbox ~]# crontab -u attacker -l
*/10 * * * * /tmp/.hidden_script
[root@vbox ~]# crontab -u attacker -r
```
### Analyser les connexions réseau actives :
```v
[root@vbox ~]# netstat -tunp
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 10.0.2.15:60192         5.83.232.126:80         TIME_WAIT   -
tcp        0      0 192.168.56.105:22       192.168.56.1:15240      ESTABLISHED 1472/sshd: root [pr
tcp        0      0 10.0.2.15:59662         213.32.5.7:443          TIME_WAIT   -
tcp        0      0 10.0.2.15:35978         193.106.119.144:80      TIME_WAIT   -
udp        0      0 10.0.2.15:53808         5.135.158.34:123        ESTABLISHED 871/chronyd
udp        0      0 192.168.56.105:68       192.168.56.100:67       ESTABLISHED 877/NetworkManager
udp        0      0 10.0.2.15:68            10.0.2.2:67             ESTABLISHED 877/NetworkManager
```

Listez les connexions actives pour repérer d'éventuelles communications malveillantes.

## Étape 2 : Configuration avancée de LVM

### 1.Créer un snapshot de sécurité pour /mnt/secure_data :
```v
[root@vbox ~]# sudo lvcreate --size 1G --snapshot --name secure_data_snapshot /dev/vg_secure/secure_data
  Reducing COW size 1.00 GiB down to maximum usable size 504.00 MiB.
  Logical volume "secure_data_snapshot" created.
```


#### Prenez un snapshot du volume logique secure_data.
```v
[root@vbox ~]# sudo lvdisplay /dev/vg_secure/secure_data_snapshot
  --- Logical volume ---
  LV Path                /dev/vg_secure/secure_data_snapshot
  LV Name                secure_data_snapshot
  VG Name                vg_secure
  LV UUID                CsYPFt-9y2Z-IfTS-CtNl-c09J-hUoK-8q20CP
  LV Write Access        read/write
  LV Creation host, time vbox, 2024-11-25 11:18:02 +0100
  LV snapshot status     active destination for secure_data
  LV Status              available
  # open                 0
  LV Size                500.00 MiB
  Current LE             125
  COW-table size         504.00 MiB
  COW-table LE           126
  Allocated to snapshot  0.01%
  Snapshot chunk size    4.00 KiB
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  - currently set to     256
  Block device           253:5

```
### 2. Tester la restauration du snapshot :

Supprimez un fichier dans /mnt/secure_data.
```v
[root@vbox ~]# rm /mnt/secure_data/
lost+found/     sensitive1.txt  sensitive2.txt
[root@vbox ~]# rm /mnt/secure_data/sensitive1.txt
rm: remove regular file '/mnt/secure_data/sensitive1.txt'? y
[root@vbox ~]# rm /mnt/secure_data/sensitive2.txt
rm: remove regular file '/mnt/secure_data/sensitive2.txt'? y
[root@vbox ~]# ls /mnt/secure_data/
lost+found
[root@vbox ~]#

```
Montez le snapshot et restaurez le fichier supprimé.
```v
[root@vbox ~]# sudo mkdir /mnt/snapshot_mount
[root@vbox ~]# sudo mount /dev/vg_secure/secure_data_snapshot /mnt/snapshot_mount
[root@vbox ~]# sudo cp /mnt/snapshot_mount/sensitive1.txt /mnt/secure_data/
[root@vbox ~]# ls /mnt/secure_data
lost+found  sensitive1.txt  sensitive2.txt
[root@vbox ~]#
```
### 3. Optimiser l’espace disque :

Si le volume logique secure_data est plein, étendez-le en ajoutant de l’espace à partir du groupe de volumes existant.
```v
[root@vbox ~]# lvextend --size +400M /dev/vg_secure/secure_data
  Insufficient free space: 100 extents needed, but only 4 available
```
## Étape 3 : Automatisation avec un script de sauvegarde

### 1. Créer un script secure_backup.sh :


Archive le contenu de /mnt/secure_data dans /backup/secure_data_YYYYMMDD.tar.gz.
Exclut les fichiers temporaires (.tmp, .log) et les fichiers cachés.
```v
[root@vbox ~]# sudo nano secure_backup.sh

[root@vbox ~]# ./secure_backup.sh
backup fini: /backup/secure_data_20241125.tar.gz
```
### 2. Ajoutez une fonction de rotation des sauvegardes :
```v
if [ "$BACKUP_COUNT" -gt "$MAX_BACKUPS" ]; then
    # supprime le backup datant
    OLD_BACKUPS=$(ls $BACKUP_DIR | grep "secure_data_" | sort | head -n $(($BACKUP_COUNT - $MAX_BACKUPS)))
    for OLD_BACKUP in $OLD_BACKUPS; do
        rm -f "$BACKUP_DIR/$OLD_BACKUP"
        echo "backup supprimé: $BACKUP_DIR/$OLD_BACKUP"
    done
fi
```
Conservez uniquement les 7 dernières sauvegardes pour économiser de l’espace.
### 3. Testez le script :
```v
[root@vbox ~]# ./secure_backup.sh
back up fini : /backup/secure_data_20241125.tar.gz
[root@vbox ~]# ls /backup
secure_data_20241125.tar.gz
```

Exécutez le script manuellement et vérifiez que les archives sont créées correctement.
### 4. Automatisez avec une tâche cron :
```v
[root@vbox ~]# crontab -e

[root@vbox ~]# crontab -l
0 3 * * * /path/to/your/secure_backup.sh
```

Planifiez le script pour qu’il s’exécute tous les jours à 3h du matin.

## Étape 4 : Surveillance avancée avec auditd

### 1.Configurer auditd pour surveiller /etc :
```v
[root@vbox ~]# sudo auditctl -a always,exit -F dir=/etc -F perm=wa -k etc_changes
perm used without an arch is slower
perm used without an arch is slower
[root@vbox ~]# sudo auditctl -l
-w /etc -p wa -k etc_changes
```

Ajoutez une règle avec auditctl pour surveiller toutes les modifications dans /etc.
### 2. Tester la surveillance :

Créez ou modifiez un fichier dans /etc et vérifiez que l’événement est enregistré dans les logs d’audit.
```v
[root@vbox ~]#mkdir /etc/pourtester
[root@vbox ~]# sudo ausearch -k etc_changes | grep 'pourtester'
type=PATH msg=audit(1732532908.075:280): item=1 name="/etc/pourtester" inode=33531 dev=fd:00 mode=040755 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 nametype=CREATE cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
[root@vbox ~]#
```
### 3.Analyser les événements :

```v
[root@vbox ~]# sudo ausearch -k etc_changes > /var/log/audit_etc.log
```
Recherchez les événements associés à la règle configurée et exportez les logs filtrés dans /var/log/audit_etc.log.


## Étape 5 : Sécurisation avec Firewalld

### 1.Configurer un pare-feu pour SSH et HTTP/HTTPS uniquement :
```v
[root@vbox ~]# sudo systemctl status firewalld
● firewalld.service - firewalld - dynamic firewall daemon
     Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled; preset: enabled)
     Active: active (running) since Mon 2024-11-25 11:33:38 CET; 39min ago
       Docs: man:firewalld(1)
   Main PID: 883 (firewalld)
      Tasks: 2 (limit: 48902)
     Memory: 45.1M
        CPU: 2.039s
     CGroup: /system.slice/firewalld.service
             └─883 /usr/bin/python3 -s /usr/sbin/firewalld --nofork --nopid

Nov 25 11:33:36 localhost systemd[1]: Starting firewalld - dynamic firewall daemon...
Nov 25 11:33:38 localhost systemd[1]: Started firewalld - dynamic firewall daemon.

[root@vbox ~]# sudo systemctl enable firewalld
sudo systemctl start firewalld

[root@vbox ~]# [root@vbox ~]# firewall-cmd --permanent --new-zone=pourtp
success
[root@vbox ~]# sudo firewall-cmd --permanent --zone=pourtp --add-service=http
success
[root@vbox ~]# sudo firewall-cmd --permanent --zone=pourtp --add-service=https
success
[root@vbox ~]# sudo firewall-cmd --permanent --zone=pourtp --add-service=ssh
success
[root@vbox ~]# sudo firewall-cmd --reload
success

[root@vbox ~]# sudo firewall-cmd --list-all
pourtp (active)
  target: default
  icmp-block-inversion: no
  interfaces: enp0s3
  sources:
  services: http https ssh
  ports:
  protocols:
  forward: no
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:
```

Autorisez uniquement les ports nécessaires pour SSH et HTTP/HTTPS.
. Bloquez toutes les autres connexions.
```v
[root@vbox ~]# sudo firewall-cmd --zone=pourtp --set-target=DROP --permanent
success

pourtp (active)
  target: DROP
  icmp-block-inversion: no
  interfaces: enp0s3 enp0s8
  sources:
  services: http https ssh
  ports:
  protocols:
  forward: no
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:
```
### 2.Bloquer des IP suspectes :
```v
[root@vbox ~]# ausearch -m avc -ts recent
<no matches>
```
À l’aide des logs d’audit et des connexions réseau, bloquez les adresses IP malveillantes identifiées.
### 3. Restreindre SSH à un sous-réseau spécifique :
Limitez l’accès SSH à votre réseau local uniquement (par exemple, 192.168.x.x).
```v
[root@vbox ~]# sudo firewall-cmd --permanent --zone=pourtp --add-source=192.168.0.0/24
sudo firewall-cmd --permanent --zone=pourtp --add-port=22/tcp
success
success
[root@vbox ~]# sudo firewall-cmd --permanent --zone=public --remove-service=ssh
success
[root@vbox ~]# sudo firewall-cmd --reload
success
[root@vbox ~]# sudo firewall-cmd --list-all
pourtp (active)
  target: DROP
  icmp-block-inversion: no
  interfaces: enp0s3 enp0s8
  sources: 192.168.0.0/24
  services: http https ssh
  ports: 22/tcp
  protocols:
  forward: no
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:
```

