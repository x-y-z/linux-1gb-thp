// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2020 Facebook */

#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "json_writer.h"
#include "main.h"

static const char * const link_type_name[] = {
	[BPF_LINK_TYPE_UNSPEC]			= "unspec",
	[BPF_LINK_TYPE_RAW_TRACEPOINT]		= "raw_tracepoint",
	[BPF_LINK_TYPE_TRACING]			= "tracing",
	[BPF_LINK_TYPE_CGROUP]			= "cgroup",
};

static int link_parse_fd(int *argc, char ***argv)
{
	if (is_prefix(**argv, "id")) {
		unsigned int id;
		char *endptr;

		NEXT_ARGP();

		id = strtoul(**argv, &endptr, 0);
		if (*endptr) {
			p_err("can't parse %s as ID", **argv);
			return -1;
		}
		NEXT_ARGP();

		return bpf_link_get_fd_by_id(id);
	} else if (is_prefix(**argv, "pinned")) {
		char *path;

		NEXT_ARGP();

		path = **argv;
		NEXT_ARGP();

		return open_obj_pinned_any(path, BPF_OBJ_LINK);
	}

	p_err("expected 'id' or 'pinned', got: '%s'?", **argv);
	return -1;
}

static void
show_link_header_json(struct bpf_link_info *info, json_writer_t *wtr)
{
	jsonw_uint_field(wtr, "id", info->id);
	if (info->type < ARRAY_SIZE(link_type_name))
		jsonw_string_field(wtr, "type", link_type_name[info->type]);
	else
		jsonw_uint_field(wtr, "type", info->type);

	jsonw_uint_field(json_wtr, "prog_id", info->prog_id);
}

static int get_prog_info(int prog_id, struct bpf_prog_info *info)
{
	__u32 len = sizeof(*info);
	int err, prog_fd;

	prog_fd = bpf_prog_get_fd_by_id(prog_id);
	if (prog_fd < 0)
		return prog_fd;

	memset(info, 0, sizeof(*info));
	err = bpf_obj_get_info_by_fd(prog_fd, info, &len);
	if (err)
		p_err("can't get prog info: %s", strerror(errno));
	close(prog_fd);
	return err;
}

static int show_link_close_json(int fd, struct bpf_link_info *info)
{
	struct bpf_prog_info prog_info;
	int err;

	jsonw_start_object(json_wtr);

	show_link_header_json(info, json_wtr);

	switch (info->type) {
	case BPF_LINK_TYPE_RAW_TRACEPOINT:
		jsonw_string_field(json_wtr, "tp_name",
				   (const char *)info->raw_tracepoint.tp_name);
		break;
	case BPF_LINK_TYPE_TRACING:
		err = get_prog_info(info->prog_id, &prog_info);
		if (err)
			return err;

		if (prog_info.type < ARRAY_SIZE(prog_type_name))
			jsonw_string_field(json_wtr, "prog_type",
					   prog_type_name[prog_info.type]);
		else
			jsonw_uint_field(json_wtr, "prog_type",
					 prog_info.type);

		if (info->tracing.attach_type < ARRAY_SIZE(attach_type_name))
			jsonw_string_field(json_wtr, "attach_type",
			       attach_type_name[info->tracing.attach_type]);
		else
			jsonw_uint_field(json_wtr, "attach_type",
					 info->tracing.attach_type);
		break;
	case BPF_LINK_TYPE_CGROUP:
		jsonw_lluint_field(json_wtr, "cgroup_id",
				   info->cgroup.cgroup_id);
		if (info->cgroup.attach_type < ARRAY_SIZE(attach_type_name))
			jsonw_string_field(json_wtr, "attach_type",
			       attach_type_name[info->cgroup.attach_type]);
		else
			jsonw_uint_field(json_wtr, "attach_type",
					 info->cgroup.attach_type);
		break;
	default:
		break;
	}

	if (!hash_empty(link_table.table)) {
		struct pinned_obj *obj;

		jsonw_name(json_wtr, "pinned");
		jsonw_start_array(json_wtr);
		hash_for_each_possible(link_table.table, obj, hash, info->id) {
			if (obj->id == info->id)
				jsonw_string(json_wtr, obj->path);
		}
		jsonw_end_array(json_wtr);
	}
	jsonw_end_object(json_wtr);

	return 0;
}

static void show_link_header_plain(struct bpf_link_info *info)
{
	printf("%u: ", info->id);
	if (info->type < ARRAY_SIZE(link_type_name))
		printf("%s  ", link_type_name[info->type]);
	else
		printf("type %u  ", info->type);

	printf("prog %u  ", info->prog_id);
}

static int show_link_close_plain(int fd, struct bpf_link_info *info)
{
	struct bpf_prog_info prog_info;
	int err;

	show_link_header_plain(info);

	switch (info->type) {
	case BPF_LINK_TYPE_RAW_TRACEPOINT:
		printf("\n\ttp '%s'  ",
		       (const char *)info->raw_tracepoint.tp_name);
		break;
	case BPF_LINK_TYPE_TRACING:
		err = get_prog_info(info->prog_id, &prog_info);
		if (err)
			return err;

		if (prog_info.type < ARRAY_SIZE(prog_type_name))
			printf("\n\tprog_type %s  ",
			       prog_type_name[prog_info.type]);
		else
			printf("\n\tprog_type %u  ", prog_info.type);

		if (info->tracing.attach_type < ARRAY_SIZE(attach_type_name))
			printf("attach_type %s  ",
			       attach_type_name[info->tracing.attach_type]);
		else
			printf("attach_type %u  ", info->tracing.attach_type);
		break;
	case BPF_LINK_TYPE_CGROUP:
		printf("\n\tcgroup_id %zu  ", (size_t)info->cgroup.cgroup_id);
		if (info->cgroup.attach_type < ARRAY_SIZE(attach_type_name))
			printf("attach_type %s  ",
			       attach_type_name[info->cgroup.attach_type]);
		else
			printf("attach_type %u  ", info->cgroup.attach_type);
		break;
	default:
		break;
	}

	if (!hash_empty(link_table.table)) {
		struct pinned_obj *obj;

		hash_for_each_possible(link_table.table, obj, hash, info->id) {
			if (obj->id == info->id)
				printf("\n\tpinned %s", obj->path);
		}
	}

	printf("\n");

	return 0;
}

static int do_show_link(int fd)
{
	struct bpf_link_info info;
	__u32 len = sizeof(info);
	char raw_tp_name[256];
	int err;

	memset(&info, 0, sizeof(info));
again:
	err = bpf_obj_get_info_by_fd(fd, &info, &len);
	if (err) {
		p_err("can't get link info: %s",
		      strerror(errno));
		close(fd);
		return err;
	}
	if (info.type == BPF_LINK_TYPE_RAW_TRACEPOINT &&
	    !info.raw_tracepoint.tp_name) {
		info.raw_tracepoint.tp_name = (unsigned long)&raw_tp_name;
		info.raw_tracepoint.tp_name_len = sizeof(raw_tp_name);
		goto again;
	}

	if (json_output)
		show_link_close_json(fd, &info);
	else
		show_link_close_plain(fd, &info);

	close(fd);
	return 0;
}

static int do_show(int argc, char **argv)
{
	__u32 id = 0;
	int err, fd;

	if (show_pinned)
		build_pinned_obj_table(&link_table, BPF_OBJ_LINK);

	if (argc == 2) {
		fd = link_parse_fd(&argc, &argv);
		if (fd < 0)
			return fd;
		return do_show_link(fd);
	}

	if (argc)
		return BAD_ARG();

	if (json_output)
		jsonw_start_array(json_wtr);
	while (true) {
		err = bpf_link_get_next_id(id, &id);
		if (err) {
			if (errno == ENOENT)
				break;
			p_err("can't get next link: %s%s", strerror(errno),
			      errno == EINVAL ? " -- kernel too old?" : "");
			break;
		}

		fd = bpf_link_get_fd_by_id(id);
		if (fd < 0) {
			if (errno == ENOENT)
				continue;
			p_err("can't get link by id (%u): %s",
			      id, strerror(errno));
			break;
		}

		err = do_show_link(fd);
		if (err)
			break;
	}
	if (json_output)
		jsonw_end_array(json_wtr);

	return errno == ENOENT ? 0 : -1;
}

static int do_pin(int argc, char **argv)
{
	int err;

	err = do_pin_any(argc, argv, link_parse_fd);
	if (!err && json_output)
		jsonw_null(json_wtr);
	return err;
}

static int do_help(int argc, char **argv)
{
	if (json_output) {
		jsonw_null(json_wtr);
		return 0;
	}

	fprintf(stderr,
		"Usage: %1$s %2$s { show | list }   [LINK]\n"
		"       %1$s %2$s pin        LINK  FILE\n"
		"       %1$s %2$s help\n"
		"\n"
		"       " HELP_SPEC_LINK "\n"
		"       " HELP_SPEC_PROGRAM "\n"
		"       " HELP_SPEC_OPTIONS "\n"
		"",
		bin_name, argv[-2]);

	return 0;
}

static const struct cmd cmds[] = {
	{ "show",	do_show },
	{ "list",	do_show },
	{ "help",	do_help },
	{ "pin",	do_pin },
	{ 0 }
};

int do_link(int argc, char **argv)
{
	return cmd_select(cmds, argc, argv, do_help);
}
