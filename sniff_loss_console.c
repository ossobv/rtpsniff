/* vim: set ts=8 sw=4 sts=4 et: */
/*======================================================================
Copyright (C) 2015 OSSO B.V. <walter+rtpsniff@osso.nl>
This file is part of RTPSniff.

RTPSniff is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

RTPSniff is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License along
with RTPSniff.  If not, see <http://www.gnu.org/licenses/>.
======================================================================*/

#include "sniff_loss.h"

#include "anysniff.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>


void out_help() {
    printf(
        "/*********************"
        " module: out (console) **********************************/\n"
        "This is the console output module.\n"
        "FIXME: define what it does...\n"
        "\n"
    );
}

int out_open(char const *config_file) {
    return 0;
}

void out_close() {
}

void out_write(uint32_t unixtime_begin, uint32_t interval, void *data) {
    struct lossstat_t *loss = data;

    time_t time_time_t;
    struct tm time_localtime;
    char timeprefix[256];

    time_time_t = time(NULL);
    localtime_r(&time_time_t, &time_localtime);
    if (strftime(timeprefix, 256, "%Y-%m-%d %H:%M:%S", &time_localtime) == 0)
        abort();

    if (loss && loss->packets != 1) {
        printf("%s: %" SCNu32 " packets (%" SCNu32 " out of order), "
               "%" SCNu64 " d-min-usec, "
               "%" SCNu64 " d-max-usec\n",
               timeprefix, loss->packets, loss->out_of_order,
               loss->min_diff_usec,
               loss->max_diff_usec);
    } else {
        printf("%s: no data\n", timeprefix);
    }
    fflush(stdout);
}
