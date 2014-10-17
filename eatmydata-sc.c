/* eatmydata-sc.c - A simple eatmydata using seccomp
 *
 * Copyright 2014 Julian Andres Klode <jak@jak-linux.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Derived from systemd code:
 *
 * Copyright 2010, 2014 Lennart Poettering
 *
 * systemd is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * systemd is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with systemd; If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>

/* Keep in sync with systemd */
int seccomp_add_secondary_archs(scmp_filter_ctx * c)
{
#if defined(__i386__) || defined(__x86_64__)
    int r;

    /* Add in all possible secondary archs we are aware of that
     * this kernel might support. */

    r = seccomp_arch_add(c, SCMP_ARCH_X86);
    if (r < 0 && r != -EEXIST)
        return r;

    r = seccomp_arch_add(c, SCMP_ARCH_X86_64);
    if (r < 0 && r != -EEXIST)
        return r;

    r = seccomp_arch_add(c, SCMP_ARCH_X32);
    if (r < 0 && r != -EEXIST)
        return r;
#endif
    return 0;
}

int main(int argc, char *argv[])
{
    static const int blacklist[] = {
        SCMP_SYS(fsync),
        SCMP_SYS(sync),
        SCMP_SYS(syncfs),
        SCMP_SYS(fdatasync),
        SCMP_SYS(msync),
        SCMP_SYS(sync_file_range),
    };

    scmp_filter_ctx seccomp;
    unsigned i;
    int r;

    if (argc < 2 || (argc < 3 && strcmp(argv[1], "--") == 0)) {
        fprintf(stderr, "Usage: %s [--] command [ command arguments ... ]\n",
                argv[0]);
        return 1;
    }

    argc--;
    argv++;

    /* Ignore trailing -- */
    if (strcmp(argv[0], "--") == 0) {
        argv++;
        argc++;
    }

    seccomp = seccomp_init(SCMP_ACT_ALLOW);
    if (!seccomp)
        return 1;

    r = seccomp_add_secondary_archs(seccomp);
    if (r < 0) {
        fprintf(stderr, "Failed to add secondary archs to seccomp filter: %s\n",
                strerror(-r));
        goto finish;
    }

    for (i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); i++) {
        r = seccomp_rule_add(seccomp, SCMP_ACT_ERRNO(0), blacklist[i], 0);
        if (r == -EFAULT)
            continue;           /* unknown syscall */
        if (r < 0) {
            fprintf(stderr, "Failed to block syscall: %s\n", strerror(-r));
            goto finish;
        }
    }

    r = seccomp_attr_set(seccomp, SCMP_FLTATR_CTL_NNP, 0);
    if (r < 0) {
        fprintf(stderr, "Failed to unset NO_NEW_PRIVS: %s\n", strerror(-r));
        goto finish;
    }

    r = seccomp_load(seccomp);
    if (r < 0)
        fprintf(stderr, "Failed to install seccomp filter: %s\n", strerror(-r));

  finish:
    seccomp_release(seccomp);

    execvp(argv[0], argv);

    perror("Could not execute");
    return 1;
}
