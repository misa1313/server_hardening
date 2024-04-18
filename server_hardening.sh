#! /bin/sh

################### Logs ###################

LOG_FILE="/root/server_hardening.log"
mv -f $LOG_FILE{,.old} &>/dev/null
echo -e "\n==============================================================================\nStarting hardening process, logs will be saved at $LOG_FILE\n==============================================================================\n" | tee -a "$LOG_FILE"

################### Logs ###################

################### Variables ###################
OS_VERSION=$(rpm -q --qf "%{VERSION}" $(rpm -q --whatprovides redhat-release) | cut -d "." -f1)

################### Variables ###################


################### Utilities ###################

#Execute and print
exe() {
    echo "\$ $@"
    "$@"
}

yes_or_no() {
    read answer ; echo $answer
    affirmative_answers=(yes Yes YES y)
    if [[ "${affirmative_answers[@]}" =~ "$answer" ]]; then
        response="yes" 
    else 
        response="no"
    fi   
}

#Replace options in config files
replace_options() {
    for ((i = 0; i < ${#s_variables[@]}; i++)); do
        s_variable="${s_variables[i]}"
        s_option="${s_options[i]}"
        grep ^$s_variable $config_file &>/dev/null; exitc=$?
        if [[ "$exitc" == 0 ]]; then 
            sed -i "s/^${s_variable}.*/${s_variable} ${s_option}/" $config_file
        else 
            echo "$s_variable $s_option" >> $config_file
        fi
    done
}

get_username() {
    while true; do 
        read -p "Enter the username: " username
        grep ^$username /etc/passwd &>/dev/null; exitc=$?
        if [[ "$exitc" == 0 ]]; then
                echo "Selected user: $username"
                break
        else 
            echo "Invalid user, choose again."
        fi 
    done
    user_home_dir=$(getent passwd "$username" | awk -F: '{print $6}')
}

################### Utilities ###################



################### SSH Hardening ###################

add_public_key() {
    get_username
    mkdir -p $user_home_dir/.ssh 
    chmod 700 $user_home_dir/.ssh 
    touch $user_home_dir/.ssh/authorized_keys
    chmod 600 $user_home_dir/.ssh/authorized_keys
    chown -R $username:$username $user_home_dir/.ssh 
    while true; do
        read -p "Enter the public key (it will be appended to the user's authorized_keys file): " pubkey
        if [[ "$pubkey" =~ ^ssh-rsa[[:space:]]+AAAAB[0-9A-Za-z+/]+[[:space:]]?.*$ ]]; then
            echo "$pubkey" | sudo tee -a $user_home_dir/.ssh/authorized_keys >/dev/null
            echo -e "\nPublic key added successfully to $user_home_dir/.ssh/authorized_keys."
            break
        else
            echo -e "Invalid public key format. Enter a valid SSH public key.\n"
        fi
    done
}

#2FA SSH
two_factor_auth() {
    exe eval 'yum install -y epel-release'
    exe eval 'yum install -y google-authenticator --enablerepo=epel'
    get_username
    echo -e "\nSetting up 2FA..."
    cp -av /etc/pam.d/sshd{,.shsbk}
    su $username -s /bin/bash -c "/usr/bin/google-authenticator --time-based"
    grep "pam_google_authenticator" /etc/pam.d/sshd &>/dev/null; exitc=$?
    if [[ "$exitc" == 1 ]]; then 
            sed -i '1i #Added by server_hardening script\nauth       required     pam_google_authenticator.so\nauth       required     pam_sepermit.so\n' /etc/pam.d/sshd
        else 
            :
    fi 
    sed -i 's/^auth[[:space:]]\+substack[[:space:]]\+password-auth/#&/' /etc/pam.d/sshd
}

ssh_hardening() {
    echo -e "\n- SSH Hardening.\n\nThe following actions will be performed:"
    echo -e "*Disable root login\n*Disable password authentication\n*Disable empty password\n*Disable '.rhosts' files\n*Disable host-based authentication\n*Enable public key authentication\n*Enabling 2FA (optional)\n"
    sleep 10
    echo -e "\nBacking up the configuration file to /etc/ssh/sshd_config.shsbk:"
    cp -av /etc/ssh/sshd_config{,.shsbk}
    s_variables=(PermitRootLogin PasswordAuthentication PermitEmptyPasswords IgnoreRhosts HostbasedAuthentication PubkeyAuthentication AuthenticationMethods)
    s_options=(no no no yes no yes publickey)
    config_file="/etc/ssh/sshd_config"
    replace_options
    echo -e "\nChanges performed:"
    exe eval 'diff /etc/ssh/sshd_config.shsbk /etc/ssh/sshd_config'

    echo -e "\nWould you like to add a public key for a non-root SSH user?"
    yes_or_no
    if [[ "$response" == "yes" ]]; then
        echo "If you don't know the username, you can use 'Ctrl + z' to stop the script now and get the name."
        sleep 10
        add_public_key
    else 
        echo -e "\nOk, moving on."
    fi
    
    echo -e "\nWould you like to configure 2FA for SSH access?"
    yes_or_no
    if [[ "$response" == "yes" ]]; then
        s_variables=(ChallengeResponseAuthentication AuthenticationMethods)
        s_options=(yes publickey,keyboard-interactive:pam)
        replace_options
        two_factor_auth
    else 
        echo -e "\nOk, moving on."
    fi

    echo -e "\n\nRestarting sshd service to apply the changes"
    exe eval 'systemctl restart sshd.service'
    echo
    echo -e "To revert changes run:\nmv /etc/pam.d/sshd.shsbk /etc/pam.d/sshd && mv /etc/ssh/sshd_config.shsbk /etc/ssh/sshd_config && systemctl restart sshd.service"
}

################### SSH Hardening ###################


################### Firewall ###################

installed_fw() {
    if [[ -f /usr/bin/imunify360-agent ]]; then
        fw="imunify360"
    elif [[ -f /usr/sbin/csf ]]; then
        fw="csf"
    elif command -v firewall-cmd &> /dev/null; then
        fw="firewalld"
    elif command -v iptables &> /dev/null; then
        fw="iptables"
    else
        echo "No supported firewall detected"
        fw="no"
    fi
}

open_port_list() {
    echo -e "First step - \nThe idea is to close all ports except a specified list of default ports."
    default_ports=(22 25 53 80 110 143 443 465 587 853 993 995 2077 2078 2079 2080 2082 2083 2086 2087 2095 2096 2222 8443)
    echo -e "The Default ports are: ${default_ports[@]}\n"

    echo -e "Want to add a port to the list, or create a new list? These are the options: \nType 'new' for a new list\nType 'add' to add ports to the default list\nType 'no' to move forward with the default ports\n" 
    read choice

    while true; do
            if [[ "$choice" == "new" ]]; then
                    read -p "Enter ports separated by space: " new_ports_input
                    IFS=' ' read -r -a ports <<< "$new_ports_input"
                    break
            elif [[ "$choice" == "add" ]]; then
                    read -p "Enter ports separated by space: " new_ports_input
                    IFS=' ' read -r -a custom_ports <<< "$new_ports_input"
                    default_ports+=( "${custom_ports[@]}" )
                    ports=("${default_ports[@]}")
                    break
            elif [[ "$choice" == "no" ]]; then
                    ports=("${default_ports[@]}")
                    break
            else
                    echo "Invalid option, choose again"
                    read choice
            fi
    done

    echo "Final list of Ports: ${ports[@]}"
}

i360_rules() {
    cp -av /etc/sysconfig/imunify360/imunify360.config{,.shsbk}
    echo "Your IP will be whitelisted. Provide your IP (you can get it by running 'curl ifconfig.me')."
    read ip_add
    /usr/bin/imunify360-agent whitelist ip add $ip_add --comment "Overriding deny mode for my IP" --full-access
    open_port_list
    echo "Changing 'port_blocking_mode' to 'DENY'..."
    /usr/bin/imunify360-agent config update '{"FIREWALL": {"port_blocking_mode": "DENY"}}' &> /dev/null
    echo "OK, now whitelisting the ports..."
    for port in "${ports[@]}"; do
        /usr/bin/imunify360-agent config update '{"FIREWALL": {"TCP_IN_IPv4":  ["'"$port"'"]}}' &> /dev/null
        echo "Port $port added (TCP_IN)"
        /usr/bin/imunify360-agent config update '{"FIREWALL": {"TCP_OUT_IPv4":  ["'"$port"'"]}}' &> /dev/null
        echo "Port $port added (TCP_OUT)"
    done
    echo -e "Ports added\n"
    echo -e "To revert changes run:\nmv /etc/sysconfig/imunify360/imunify360.config.shsbk /etc/sysconfig/imunify360/imunify360.config"
}

csf_rules() {
    cp -av /etc/csf/csf.conf{,.shsbk}
    echo "Your IP will be whitelisted. Provide your IP (you can get it by running 'curl ifconfig.me')."
    read ip_add
    /usr/sbin/csf -a $ip_add
    open_port_list
    IFS=,
    ports=$(printf "%s" "${ports[*]}")
    echo "OK, now whitelisting the ports..."
    sed -i "s/^TCP_IN =.*/TCP_IN = \"$ports\"/" /etc/csf/csf.conf
    sed -i "s/^TCP_OUT =.*/TCP_OUT = \"$ports\"/" /etc/csf/csf.conf
    /usr/sbin/csf -a
    echo -e "Ports added, restarting CSF...\n"
    exe eval '/usr/sbin/csf -r'
    echo -e "\nTo revert changes run:\nmv /etc/csf/csf.conf.shsbk /etc/csf/csf.conf && /usr/sbin/csf -r"
}

firewalld_rules() {
    cp -av /etc/firewalld{,.shsbk}
    echo "Your IP will be whitelisted. Provide your IP (you can get it by running 'curl ifconfig.me')."
    read ip_add
    /usr/bin/firewall-cmd --permanent --zone=public --add-source="$ip_add"
    open_port_list
    echo "OK, now whitelisting the ports..."
    for port in "${ports[@]}"
    do
        /usr/bin/firewall-cmd --permanent --zone=public --add-port="$port/tcp"
    done
    echo -e "Ports added, restarting firewalld...\n"
    exe eval '/usr/bin/firewall-cmd --reload'
    echo -e "\nTo revert changes run:\nmv /etc/firewalld{,.temp} && mv /etc/firewalld.shsbk /etc/firewalld && /usr/bin/firewall-cmd --reload"
}

iptables_rules() {
    /usr/sbin/iptables-save  > /root/iptables_shsbk.txt
    echo "Your IP will be whitelisted. Provide your IP (you can get it by running 'curl ifconfig.me')."
    read ip_add
    ssh_port=$( (grep ^Port alskg &>/dev/null && awk {'print $2'} $_) || (echo "22"))
    /usr/sbin/iptables -A INPUT -s $ip_add -p tcp --dport $ssh_port -j ACCEPT
    open_port_list
    echo "OK, now whitelisting the ports..."
    /usr/sbin/iptables -F
    /usr/sbin/iptables -X
    /usr/sbin/iptables -Z
    for port in "${ports[@]}"; do
        /usr/sbin/iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
    done
    /usr/sbin/iptables -A INPUT -j DROP
    echo -e "Ports added, restarting iptables...\n"
    /usr/bin/firewall-cmd --reload
    echo -e "\nTo revert changes run:\n/usr/sbin/iptables-restore < /root/iptables_shsbk.txt"
}

fw_hardening() {
    echo -e "\n- Firewall Configuration.\n\nThe following action will be performed:" 
    echo -e "*Block unneeded ports\n"
    sleep 10
    installed_fw
    if [[ "$fw" != "no" ]]; then 
        echo -e "Found firewall $fw\n"
        case $fw in
            "imunify360")
                i360_rules;;
            "csf")
                csf_rules;;
            "firewalld")
                firewalld_rules;;
            "iptables")
                iptables_rules;;
        esac

    else 
        echo -e "\nSkipping this section"
    fi

}

################### Firewall ###################


################### User Password Policy ###################

bk_pam_files() {
    files=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth" "/etc/security/pwquality.conf" "/etc/security/faillock.conf")
    for file in "${files[@]}"; do
        if [ ! -f "$file.shsbk" ]; then
            cp -av $file{,.shsbk} 2>/dev/null
        else
            :
        fi
    done
}

check_authselect() {
    yum upgrade -y pam authselect &> /dev/null || yum install -y pam authselect &> /dev/null
    /usr/bin/authselect check; exitc=$?
    if [[ "$exitc" == 0 ]]; then 
            :
        else 
            echo -e "\nNO Authselect profile detected, using 'sssd' as default..."
            exe eval '/usr/bin/authselect select sssd --force'
    fi 
}

pam_faillock_setup() {
    echo -e "\n**Configuring pam_faillock\n"
    if [[ "$OS_VERSION" == "7" ]]; then
        bk_pam_files; echo
        grep "pam_faillock.so" /etc/pam.d/sshd &>/dev/null; exitc=$?
        if [[ "$exitc" == 1 ]]; then 
                sed -i '1i #Added by server_hardening script\nauth        required      pam_faillock.so preauth silent audit deny=3 unlock_time=600\npam_faillock.so authfail audit deny=3 unlock_time=600 \naccount     required      pam_faillock.so' /etc/pam.d/password-auth
                sed -i '1i #Added by server_hardening script\nauth        required      pam_faillock.so preauth silent audit deny=3 unlock_time=600\npam_faillock.so authfail audit deny=3 unlock_time=600 \naccount     required      pam_faillock.so' /etc/pam.d/system-auth
                echo 
                echo -e "To revert changes run:\nmv /etc/pam.d/system-auth.shsbk /etc/pam.d/system-auth && mv /etc/pam.d/password-auth.shsbk /etc/pam.d/password-auth"
            else 
                :
        fi 
    elif [[ "$OS_VERSION" == "8" || "$OS_VERSION" == "9" ]]; then 
        bk_pam_files; echo
        check_authselect
        s_variables=("deny =" "unlock_time =" "fail_interval =" "silent")
        s_options=(4 1200 600 "")
        config_file="/root/faillock.conf"
        replace_options
        exe eval '/usr/bin/authselect enable-feature with-faillock'
        echo 
        echo -e "To revert changes run:\n/usr/bin/authselect disable-feature with-faillock"
    else 
        echo -e "\nUnsupported system detected, skipping...\n"
    fi
}

pam_pwquality_setup() {
    echo -e "\n**Configuring pam_pwquality\n"
    if [[ "$OS_VERSION" == "8" || "$OS_VERSION" == "9" || "$OS_VERSION" == "7" ]]; then 
        bk_pam_files; echo
        s_variables=("minlen" "dcredit" "ucredit" "lcredit" "ocredit" "minclass" "maxrepeat" "maxclassrepeat" "difok" "usercheck")
        s_options=("= 9" "= -1" "= -1" "= 1" "= 1" "= 1" "= 2" "= 3" "= 5" "= 1")
        config_file="/etc/security/pwquality.conf"
        replace_options

        echo -e "File "/etc/security/pwquality.conf" properly configured\n" 
        echo -e "To revert changes run:\nmv /etc/security/pwquality.conf.shsbk /etc/security/pwquality.conf"
    else 
        echo -e "\nUnsupported system detected, skipping...\n"
    fi
}

pam_pwhistory_setup() {
    echo -e "\n**Configuring pam_pwhistory\n"
    if [[ "$OS_VERSION" == "7" ]]; then
        bk_pam_files; echo
        op1="password    requisite    pam_pwhistory.so remember=5 use_authtok"
        op2="password    sufficient   pam_unix.so sha512 shadow nullok try_first_pass use_authtok"
        files=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
        for file in "${files[@]}"; do
            # Add op1 before pam_unix.so
            sed -i "/^password.*pam_unix.so/s/^/$op1\n/" "$file"
            # Add op2 before pam_unix.so
            sed -i "/^password.*pam_unix.so/s/^/$op2\n/" "$file"
        done
        echo -e "Files "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" properly configured\n"
        echo -e "To revert changes run:\nmv /etc/pam.d/system-auth.shsbk /etc/pam.d/system-auth && mv /etc/pam.d/password-auth.shsbk /etc/pam.d/password-auth"
    elif [[ "$OS_VERSION" == "8" || "$OS_VERSION" == "9" ]]; then 
        bk_pam_files; echo
        check_authselect
        exe eval '/usr/bin/authselect enable-feature with-pwhistory'
        echo 
        echo -e "To revert changes run:\n/usr/bin/authselect disable-feature with-pwhistory"
    else 
        echo -e "\nUnsupported system detected, skipping...\n"
    fi
}

change_pass_setup() {
    echo -e "\n**Setting user password change policy\n"
    cp -av /etc/shadow{,.shsbk}
    regular_users=$(awk -F: '$3 >= 1000 {print $1}' /etc/passwd |grep -v nobody)
    if [[ -z "$regular_users" ]]; then
        echo -e "\nNo valid users found, skipping...\n"
    else
        echo "$regular_users" | while read -r user; do
            exe eval "chage -M 60 -m 7 -W 7 $user"
        done
        echo -e "Setup completed\n"
        echo -e "To revert changes run:\nmv /etc/shadow.shsbk /etc/shadow"
    fi
}

user_pass_policy() {
    echo -e "\n- User password policy configuration.\n\nThe following action will be performed:" 
    echo -e "*Enable pam modules: pam_faillock, pam_pwquality, and pam_pwhistory\n*Users with UID above 1000, will be forced to change passwords every 60 days\n"
    sleep 10
    pam_faillock_setup
    pam_pwquality_setup
    pam_pwhistory_setup
    change_pass_setup
}

################### User Password Policy ###################

ssh_hardening  | tee -a "$LOG_FILE"
fw_hardening | tee -a "$LOG_FILE"
user_pass_policy | tee -a "$LOG_FILE"
echo -e "\n\n\e[32mAll set, the process is complete.\e[0m" | tee -a "$LOG_FILE"

################### WIP ###################
#Automatic updates
#SELinux
#sysctl.conf 
#/tmp
#Fail2ban
#Apache/Nginx
#USB devices 
