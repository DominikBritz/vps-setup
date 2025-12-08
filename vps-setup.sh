#!/bin/bash
# Setup a Debian Virtual Private Server (VPS) hosted in Hetzner
# This script follows the guidelines recommended by Hetzner:
#  - https://community.hetzner.com/tutorials/setup-ubuntu-20-04
#
# This script is developed for Ubuntu.

# Add non-interactive apt helper
APT_INSTALL="apt-get install -y -qq"


if [ -z "$1" ] || [ "$1" != "--confirm" ]; then
    echo "ATTENTION!!"
    echo "This command will disable password authentication and root login."
    echo "This means that once you logout from the current session you will no longer be able to login again as root."
    echo "After running make sure you can login with the newly created sysadmin user BEFORE closing this session."
    echo ""
    echo "If you understand this, execute the command with --confirm argument."
    exit 1
fi

update_apt() {
    echo "Updating apt-get repository and upgrading the system..."
    apt-get update -qq
    apt-get upgrade -y -qq
}

setup_firewall() {
  echo "Installing firewall and opening ports 1222 (ssh), 80, 443, 51820/udp and 21820/udp..."
  $APT_INSTALL ufw
  ufw default deny incoming
  ufw allow 1222/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow in proto udp to any port 51820
  ufw allow in proto udp to any port 21820
  # Force enable to avoid interactive confirmation on Ubuntu
  ufw --force enable
}

setup_ssh_daemon() {
  echo "Disabbling password authentication, root login and changing SSH port to 1222..."
  sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
  # prohibit-password is Debian's default
  sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
  sed -i 's/#Port 22/Port 1222/' /etc/ssh/sshd_config
  # restart whichever ssh service exists on Debian/Ubuntu
  systemctl restart ssh || systemctl restart sshd || true
}

setup_fail2ban() {
  echo "Installing and enabling fail2ban (using default configs)..."
  $APT_INSTALL fail2ban
  # Write fail2ban jail.local using a heredoc to preserve newlines
  sudo tee /etc/fail2ban/jail.local > /dev/null <<'EOF'
[sshd]
backend=systemd
enabled=true
EOF
  # python3-systemd may be required on some distros; install if available
  $APT_INSTALL python3-systemd || true
   systemctl enable fail2ban
   systemctl start fail2ban
}

setup_logwatch() {
  echo "Installing and enabling logwatch (using default configs)..."
  $APT_INSTALL logwatch
}

install_utils() {
  echo "Installing util tools: htop, vim and git..."
  $APT_INSTALL htop vim git
}

add_sysadmin_user() {
  echo "Adding a sysadmin user with sudo permission..."
  
  read -p "Enter the new username: " NEW_USER

  # Check if user already exists
  if id "$NEW_USER" &>/dev/null; then
      echo "User $NEW_USER already exists."
      read -p "Do you want to give this user sudo access? [y/N]: " GRANT_SUDO
      if [[ "$GRANT_SUDO" =~ ^[Yy]$ ]]; then
          usermod -aG sudo "$NEW_USER" 2>/dev/null || usermod -aG wheel "$NEW_USER"
          echo "Sudo access granted to $NEW_USER."
      else
          echo "Skipping sudo access setup."
      fi
  else
    # Create user
    useradd -m "$NEW_USER"
    passwd "$NEW_USER"
    usermod -aG sudo "$NEW_USER" 2>/dev/null || usermod -aG wheel "$NEW_USER"

    # SSH Key Setup
    echo
    echo "Choose SSH setup method:"
    echo "1) Paste your existing public key"
    echo "2) Generate a new SSH keypair for this user"
    echo "3) Skip (not recommended)"
    read -p "Enter your choice [1-3]: " SSH_CHOICE

    if [[ "$SSH_CHOICE" == "1" ]]; then
        read -p "Paste the SSH public key: " USER_SSH_KEY
        mkdir -p /home/$NEW_USER/.ssh
        echo "$USER_SSH_KEY" > /home/$NEW_USER/.ssh/authorized_keys
        chmod 700 /home/$NEW_USER/.ssh
        chmod 600 /home/$NEW_USER/.ssh/authorized_keys
        chown -R $NEW_USER:$NEW_USER /home/$NEW_USER/.ssh
        echo "Public key added for $NEW_USER."

    elif [[ "$SSH_CHOICE" == "2" ]]; then
        mkdir -p /root/ssh-keys
        ssh-keygen -t rsa -b 4096 -f /root/ssh-keys/${NEW_USER}_id_rsa -N ""
        mkdir -p /home/$NEW_USER/.ssh
        cat /root/ssh-keys/${NEW_USER}_id_rsa.pub > /home/$NEW_USER/.ssh/authorized_keys
        chmod 700 /home/$NEW_USER/.ssh
        chmod 600 /home/$NEW_USER/.ssh/authorized_keys
        chown -R $NEW_USER:$NEW_USER /home/$NEW_USER/.ssh
        echo "SSH keypair generated for $NEW_USER."
        echo
        echo "⚠️ Copy and store the following private key securely (you'll need it to log in):"
        echo
        cat /root/ssh-keys/${NEW_USER}_id_rsa
        echo
        echo "Saved at: /root/ssh-keys/${NEW_USER}_id_rsa"
    else
        echo "⚠️ No SSH key configured. Ensure password login is enabled or you have console/VNC access."
    fi
  fi

}

finish_message() {
  echo "Configuration Finished!! Before closing this session check that you can ssh in using port 1222 with the newly created sysadmin account."
}

install_docker() {
  echo "Installing latest version of docker..."
  # Add Docker's official GPG key:
  $APT_INSTALL ca-certificates curl
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc

  # Add the repository to Apt sources:
  tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF

  apt update

  $APT_INSTALL docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  echo "Adding sysadmin user to docker group..."
  # Use the username provided earlier (if any)
  if [ -n "$NEW_USER" ]; then
    echo "Adding $NEW_USER to docker group..."
    usermod -aG docker "$NEW_USER"
  else
    echo "No NEW_USER set; skipping adding user to docker group."
  fi
}

unattended_upgrades() {
  # Install and enable unattended-upgrades for automatic security upgrades.
  # https://wiki.debian.org/PeriodicUpdates?action=show&redirect=UnattendedUpgrades
  echo "Ensuring unattended-upgrades is installed and running..."
  $APT_INSTALL unattended-upgrades
   dpkg-reconfigure -f noninteractive unattended-upgrades
}

create_weekly_upgrade_cron() {
  echo "Creating weekly upgrade cron job (Sun 01:00)..."
  cat > /etc/cron.d/weekly-upgrade <<'EOF'
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 1 * * 0 root /usr/bin/apt update && /usr/bin/apt dist-upgrade -y && /usr/bin/apt autoremove -y && /sbin/reboot >> /var/log/weekly-upgrade.log 2>&1
EOF
  chmod 644 /etc/cron.d/weekly-upgrade
  touch /var/log/weekly-upgrade.log
  chown root:root /var/log/weekly-upgrade.log
  echo "Wrote /etc/cron.d/weekly-upgrade and created /var/log/weekly-upgrade.log"
}

main () {
    update_apt
    setup_firewall
    setup_ssh_daemon
    setup_fail2ban
    setup_logwatch
    install_utils
    add_sysadmin_user
    install_docker
    unattended_upgrades
    create_weekly_upgrade_cron
    finish_message
}

main
