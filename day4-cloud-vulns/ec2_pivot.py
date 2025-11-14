import paramiko

key = paramiko.RSAKey.from_private_key_file('~/.ssh/vuln-key')
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('54.123.45.67', username='ubuntu', pkey=key)
stdin, stdout, stderr = ssh.exec_command('whoami')
print("Pivoted: " + stdout.read().decode())
ssh.close()
