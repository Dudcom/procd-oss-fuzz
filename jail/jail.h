/*
 * Copyright (C) 2015 Etienne Champetier <champetier.etienne@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef _JAIL_JAIL_H_
#define _JAIL_JAIL_H_

int mount_bind(const char *root, const char *path, int readonly, int error);
int ns_open_pid(const char *nstype, const pid_t target_ns);

#endif
