#ifndef INCLUDED_SNIFF_LOSS_H
#define INCLUDED_SNIFF_LOSS_H
/* vim: set ts=8 sw=4 sts=4 et: */
/*======================================================================
Copyright (C) 2015 OSSO B.V. <walter+rtpsniff@osso.nl>
This file is part of RTPSniff.

RTPSniff is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

RTRSniff is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License along
with RTPSniff.  If not, see <http://www.gnu.org/licenses/>.
======================================================================*/

#include <inttypes.h>

struct lossstat_t {
    uint64_t prev;

    uint64_t min_diff_usec;
    uint64_t max_diff_usec;

    uint32_t packets;
    uint32_t out_of_order;
};

#endif /* INCLUDED_SNIFF_LOSS_H */
