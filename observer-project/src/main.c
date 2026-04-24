// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include "common.h"
#include "observer.skel.h"

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

const char *argp_program_version = "observer 0.0";
const char *argp_program_bug_address = "email@example.com";
const char argp_program_doc[] = "Linux Observer application.\n"
				"\n"
				"It gathers TCP/UDP connection information and attempts \n"
				"to decode protocols\n"
				"\n"
				"USAGE: ./observe\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_open(void *ctx, void *data, size_t data_sz)
{
	const struct socket_open_event_t *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-5s %-16lld %-7d %-7d %-16lld %-15s\n", ts, "OPEN ", e->timestamp_ns, e->conn_id.pid, e->conn_id.fd,
			e->conn_id.tsid, inet_ntoa(e->addr.sin_addr));

	return 0;
}

static int handle_close(void *ctx, void *data, size_t data_sz)
{
	const struct socket_close_event_t *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-5s %-16lld %-7d %-7d %-16lld %-9lld %-9lld\n", ts, "CLOSE", e->timestamp_ns, e->conn_id.pid, e->conn_id.fd,
			e->conn_id.tsid, e->wr_bytes, e->rd_bytes);

	return 0;
}

static int handle_data(void *ctx, void *data, size_t data_sz)
{
	const struct socket_data_event_t *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-5s %-16lld %-7d %-7d %-7lld %-7s %-7d %-7lld %-16s\n", ts, "DATA ", e->attr.timestamp_ns, e->attr.conn_id.pid, e->attr.conn_id.fd,
			e->attr.conn_id.tsid, (e->attr.direction == kIngress ? "Ingress" : "Egress"), e->attr.msg_size, e->attr.pos, e->msg);

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *socket_open_events = NULL;
	struct ring_buffer *socket_close_events = NULL;
	struct ring_buffer *socket_data_events = NULL;
	struct observer_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = observer_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = observer_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = observer_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up the socket open events ring buffer polling */
	socket_open_events = ring_buffer__new(bpf_map__fd(skel->maps.socket_open_events), handle_open, NULL, NULL);
	if (!socket_open_events) {
		err = -1;
		fprintf(stderr, "Failed to create socket_open_events ring buffer\n");
		goto cleanup;
	}

	/* Set up the socket close events ring buffer polling */
	socket_close_events = ring_buffer__new(bpf_map__fd(skel->maps.socket_close_events), handle_close, NULL, NULL);
	if (!socket_close_events) {
		err = -1;
		fprintf(stderr, "Failed to create socket_close_events ring buffer\n");
		goto cleanup;
	}
	
	/* Set up the socket data events ring buffer polling */
	socket_data_events = ring_buffer__new(bpf_map__fd(skel->maps.socket_data_events), handle_data, NULL, NULL);
	if (!socket_data_events) {
		err = -1;
		fprintf(stderr, "Failed to create socket_data_events ring buffer\n");
		goto cleanup;
	}
	/* Process events */
	printf("%-8s %-5s %-16s %-7s %-7s %s\n", "TIME", "EVENT", "COMM", "PID", "PPID",
	       "FILENAME/EXIT CODE");
	while (!exiting) {

		err = ring_buffer__poll(socket_open_events, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling socket_open_events ring buffer: %d\n", err);
			break;
		}

		err = ring_buffer__poll(socket_close_events, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling socket_close_events ring buffer: %d\n", err);
			break;
		}

		err = ring_buffer__poll(socket_data_events, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling socket_data_events ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(socket_open_events);
	ring_buffer__free(socket_close_events);
	ring_buffer__free(socket_data_events);
	observer_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}