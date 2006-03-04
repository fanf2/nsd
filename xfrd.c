/*
 * xfrd.h - XFR (transfer) Daemon header file. Coordinates SOA updates.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "xfrd.h"
#include "options.h"
#include "util.h"
#include "netio.h"
#include "region-allocator.h"
#include "nsd.h"

/* the daemon state */
static xfrd_state_t* xfrd = 0;

/* manage interprocess communication with server_main process */
static void xfrd_handle_ipc(netio_type *netio, 
	netio_handler_type *handler, netio_event_types_type event_types);
/* main xfrd loop */
static void xfrd_main();
/* shut down xfrd, close sockets. */
static void xfrd_shutdown();
/* create zone rbtree at start */
static void xfrd_init_zones();
/* free up memory used by main database */
static void xfrd_free_namedb();
/* handle zone timeout, event */
static void xfrd_handle_zone(netio_type *netio, 
	netio_handler_type *handler, netio_event_types_type event_types);
/* copy SOA info from rr to soa struct. Memleak if prim.ns or email changes in soa. */
static void xfrd_copy_soa(xfrd_soa_t* soa, rr_type* rr);
/* set refresh timer of zone to refresh at time now */
static void xfrd_set_refresh_now(xfrd_zone_t* zone);
/* get the current time epoch. Cached for speed. */
static time_t xfrd_time();
/* read state from disk */
static void xfrd_read_state();
/* write state to disk */
static void xfrd_write_state();

void xfrd_init(int socket, struct nsd* nsd)
{
#ifndef NDEBUG
	assert(xfrd == 0);
#endif
	/* to setup signalhandling */
	nsd->server_kind = NSD_SERVER_BOTH;

	region_type* region = region_create(xalloc, free);
	xfrd = (xfrd_state_t*)region_alloc(region, sizeof(xfrd_state_t));
	memset(xfrd, 0, sizeof(xfrd_state_t));
	xfrd->region = region;
	xfrd->xfrd_start_time = time(0);
	xfrd->netio = netio_create(xfrd->region);
	xfrd->nsd = nsd;

	xfrd->reload_time = 0;

	xfrd->ipc_handler.fd = socket;
	xfrd->ipc_handler.timeout = NULL;
	xfrd->ipc_handler.user_data = xfrd;
	xfrd->ipc_handler.event_types = NETIO_EVENT_READ;
	xfrd->ipc_handler.event_handler = xfrd_handle_ipc;
	netio_add_handler(xfrd->netio, &xfrd->ipc_handler);

	log_msg(LOG_INFO, "xfrd pre-startup");
	xfrd_init_zones();
	xfrd_free_namedb();
	xfrd_read_state();

	log_msg(LOG_INFO, "xfrd startup");
	xfrd_main();
}

static void 
xfrd_main()
{
	xfrd->shutdown = 0;
	while(!xfrd->shutdown)
	{
		/* dispatch may block for a longer period, so current is gone */
		xfrd->got_time = 0;
		if(netio_dispatch(xfrd->netio, NULL, 0) == -1) {
			if (errno != EINTR) {
				log_msg(LOG_ERR, 
					"xfrd netio_dispatch failed: %s", 
					strerror(errno));
			}
		}
		if(xfrd->nsd->signal_hint_quit || xfrd->nsd->signal_hint_shutdown)
			xfrd->shutdown = 1;
	}
	xfrd_shutdown();
}

static void xfrd_shutdown()
{
	log_msg(LOG_INFO, "xfrd shutdown");
	xfrd_write_state();
	close(xfrd->ipc_handler.fd);
	region_destroy(xfrd->region);
	region_destroy(xfrd->nsd->options->region);
	region_destroy(xfrd->nsd->region);
	exit(0);
}

static void
xfrd_handle_ipc(netio_type* ATTR_UNUSED(netio), 
	netio_handler_type *handler, 
	netio_event_types_type event_types)
{
        sig_atomic_t cmd;
        int len;
        if (!(event_types & NETIO_EVENT_READ)) {
                return;
        }

        if ((len = read(handler->fd, &cmd, sizeof(cmd))) == -1) {
                log_msg(LOG_ERR, "xfrd_handle_ipc: read: %s",
                        strerror(errno));
                return;
        }
        if (len == 0)
        {
		/* parent closed the connection. Quit */
		xfrd->shutdown = 1;
		return;
        }

        switch (cmd) {
        case NSD_QUIT:
        case NSD_SHUTDOWN:
                xfrd->shutdown = 1;
                break;
        default:
                log_msg(LOG_ERR, "xfrd_handle_ipc: bad mode %d", (int)cmd);
                break;
        }

}

static void xfrd_init_zones()
{
	zone_type *dbzone;
	zone_options_t *zone_opt;
	xfrd_zone_t *xzone;
	const dname_type* dname;
#ifndef NDEBUG
	assert(xfrd->zones == 0);
	assert(xfrd->nsd->db != 0);
#endif
	xfrd->zones = rbtree_create(xfrd->region, 
		(int (*)(const void *, const void *)) dname_compare);
	
	for(zone_opt = xfrd->nsd->options->zone_options; 
		zone_opt; zone_opt=zone_opt->next)
	{
		log_msg(LOG_INFO, "Zone %s\n", zone_opt->name);
		if(!zone_is_slave(zone_opt)) {
			log_msg(LOG_INFO, "skipping master zone %s\n", zone_opt->name);
			continue;
		}
		dname = dname_parse(xfrd->region, zone_opt->name);
		if(!dname) {
			log_msg(LOG_ERR, "xfrd: Could not parse zone name %s.", zone_opt->name);
			continue;
		}
		dbzone = domain_find_zone(domain_table_find(xfrd->nsd->db->domains, dname));
		if(!dbzone)
			log_msg(LOG_INFO, "xfrd: adding empty zone %s\n", zone_opt->name);
		else log_msg(LOG_INFO, "xfrd: adding filled zone %s\n", zone_opt->name);
		
		xzone = (xfrd_zone_t*)region_alloc(xfrd->region,
			sizeof(xfrd_zone_t));
		memset(xzone, 0, sizeof(xfrd_zone_t));
		xzone->apex = dname;
		xzone->apex_str = zone_opt->name;
		xzone->zone_state = xfrd_zone_refreshing;
		xzone->zone_options = zone_opt;
		xzone->next_master = xzone->zone_options->request_xfr;
		xzone->next_master_num = 0;

		xzone->soa_nsd_acquired = 0;
		xzone->soa_disk_acquired = 0;
		xzone->soa_notified_acquired = 0;

		xzone->zone_handler.fd = -1;
		xzone->zone_handler.timeout = 0;
		xzone->zone_handler.user_data = xzone;
		xzone->zone_handler.event_types = NETIO_EVENT_READ|NETIO_EVENT_TIMEOUT;
		xzone->zone_handler.event_handler = xfrd_handle_zone;
		netio_add_handler(xfrd->netio, &xzone->zone_handler);
		
		if(dbzone && dbzone->soa_rrset && dbzone->soa_rrset->rrs) {
			xzone->soa_nsd_acquired = xfrd_time();
			xzone->soa_disk_acquired = xfrd_time();
			/* we only use the first SOA in the rrset */
			xfrd_copy_soa(&xzone->soa_nsd, dbzone->soa_rrset->rrs);
			xfrd_copy_soa(&xzone->soa_disk, dbzone->soa_rrset->rrs);
			/* set refreshing anyway, we have data but it may be old */
		}
		xfrd_set_refresh_now(xzone);

		xzone->node.key = dname;
		rbtree_insert(xfrd->zones, (rbnode_t*)xzone);
	}
	log_msg(LOG_INFO, "xfrd: started server %d secondary zones", (int)xfrd->zones->count);
}

static void xfrd_free_namedb()
{
	namedb_close(xfrd->nsd->db);
	xfrd->nsd->db = 0;
}

static void xfrd_handle_zone(netio_type *netio, 
	netio_handler_type *handler, netio_event_types_type event_types)
{
	xfrd_zone_t* zone = (xfrd_zone_t*)handler->user_data;
	log_msg(LOG_INFO, "Got zone %s timeout handler", zone->apex_str);
	handler->timeout = 0;
}

static time_t xfrd_time()
{
	if(!xfrd->got_time) {
		xfrd->current_time = time(0);
		xfrd->got_time = 1;
	}
	return xfrd->current_time;
}

static void xfrd_copy_soa(xfrd_soa_t* soa, rr_type* rr)
{
	if(rr->type != TYPE_SOA || rr->rdata_count != 7) {
		log_msg(LOG_ERR, "xfrd: copy_soa called with bad rr, type %d rrs %d.", 
			rr->type, rr->rdata_count);
		return;
	}
	log_msg(LOG_INFO, "xfrd: copy_soa rr, type %d rrs %d, ttl %d.", 
			rr->type, rr->rdata_count, rr->ttl);
	soa->type = htons(rr->type);
	soa->klass = htons(rr->klass);
	soa->ttl = htonl(rr->ttl);
	soa->rdata_count = htons(rr->rdata_count);
	if(soa->prim_ns==0 || dname_compare(soa->prim_ns, 
		domain_dname(rdata_atom_domain(rr->rdatas[0])))!=0) {
		soa->prim_ns = dname_copy(xfrd->region, 
			domain_dname(rdata_atom_domain(rr->rdatas[0])));
	}
	if(soa->email==0 || dname_compare(soa->email, 
		domain_dname(rdata_atom_domain(rr->rdatas[1])))!=0) {
		soa->email = dname_copy(xfrd->region, 
			domain_dname(rdata_atom_domain(rr->rdatas[1])));
	}
	/* already in network format */
	soa->serial = *(uint32_t*)rdata_atom_data(rr->rdatas[2]);
	soa->refresh = *(uint32_t*)rdata_atom_data(rr->rdatas[3]);
	soa->retry = *(uint32_t*)rdata_atom_data(rr->rdatas[4]);
	soa->expire = *(uint32_t*)rdata_atom_data(rr->rdatas[5]);
	soa->minimum = *(uint32_t*)rdata_atom_data(rr->rdatas[6]);
}

static void xfrd_set_refresh_now(xfrd_zone_t* zone) 
{
	zone->zone_state = xfrd_zone_refreshing;
	zone->zone_handler.fd = -1;
	zone->zone_handler.timeout = &zone->timeout;
	zone->timeout.tv_sec = xfrd_time();
	zone->timeout.tv_nsec = 0;
}

/* quick tokenizer, reads words separated by whitespace.
   No quoted strings. Comments are skipped (#... eol). */
static char* xfrd_read_token(FILE* in)
{
	static char buf[4000];
	while(1) {
		if(fscanf(in, " %3990s", buf) != 1) return 0;
		if(buf[0] != '#') return buf;
		if(!fgets(buf, sizeof(buf), in)) return 0;
	}
}

static int xfrd_read_i16(FILE *in, uint16_t* v)
{
	char* p = xfrd_read_token(in);
	if(!p) return 0;
	*v=atoi(p);
	return 1;
}

static int xfrd_read_i32(FILE *in, uint32_t* v)
{
	char* p = xfrd_read_token(in);
	if(!p) return 0;
	*v=atoi(p);
	return 1;
}

static int xfrd_read_time_t(FILE *in, time_t* v)
{
	char* p = xfrd_read_token(in);
	if(!p) return 0;
	*v=atol(p);
	return 1;
}

static int xfrd_read_check_str(FILE* in, const char* str)
{
	char *p = xfrd_read_token(in);
	if(!p) return 0;
	if(strcmp(p, str) != 0) return 0;
	return 1;
}

static int xfrd_read_state_soa(FILE* in, const char* id_acquired,
	const char* id, xfrd_soa_t* soa, time_t* soatime, 
	region_type* region)
{
	char *p;

	if(!xfrd_read_check_str(in, id_acquired) ||
	   !xfrd_read_time_t(in, soatime) 
	) return 0;
	if(*soatime == 0) return 1;
	if(!xfrd_read_check_str(in, id) ||
	   !xfrd_read_i16(in, &soa->type) ||
	   !xfrd_read_i16(in, &soa->klass) ||
	   !xfrd_read_i32(in, &soa->ttl) ||
	   !xfrd_read_i16(in, &soa->rdata_count)
	) return 0;
	soa->type = htons(soa->type);
	soa->klass = htons(soa->klass);
	soa->ttl = htonl(soa->ttl);
	soa->rdata_count = htons(soa->rdata_count);

	if(!(p=xfrd_read_token(in))) return 0;
	soa->prim_ns = dname_parse(region, p);
	if(!soa->prim_ns) return 0;

	if(!(p=xfrd_read_token(in))) return 0;
	soa->email = dname_parse(region, p);
	if(!soa->email) return 0;

	if(!xfrd_read_i32(in, &soa->serial) ||
	   !xfrd_read_i32(in, &soa->refresh) ||
	   !xfrd_read_i32(in, &soa->retry) ||
	   !xfrd_read_i32(in, &soa->expire) ||
	   !xfrd_read_i32(in, &soa->minimum)
	) return 0;
	soa->serial = htonl(soa->serial);
	soa->refresh = htonl(soa->refresh);
	soa->retry = htonl(soa->retry);
	soa->expire = htonl(soa->expire);
	soa->minimum = htonl(soa->minimum);
	return 1;
}

static void xfrd_read_state()
{
	const char* statefile = xfrd->nsd->options->xfrdfile;
	FILE *in;
	uint32_t filetime = 0;
	uint32_t numzones, i;
	region_type *tempregion;
	if(!statefile) statefile = "nsd.xfrdstate";

	tempregion = region_create(xalloc, free);
	if(!tempregion) return;

	in = fopen(statefile, "r");
	if(!in) {
		if(errno != ENOENT) {
			log_msg(LOG_ERR, "xfrd: Could not open file %s for reading: %s",
				statefile, strerror(errno));
		}
		else log_msg(LOG_INFO, "xfrd: no file %s. refreshing all zones.",
			statefile);
		return;
	}
	if(!xfrd_read_check_str(in, XFRD_FILE_MAGIC) ||
	   !xfrd_read_check_str(in, "filetime:") ||
	   !xfrd_read_i32(in, &filetime) ||
	   (time_t)filetime > xfrd_time()+15 ||
	   !xfrd_read_check_str(in, "numzones:") ||
	   !xfrd_read_i32(in, &numzones)
	  ) 
	{
		log_msg(LOG_ERR, "xfrd: corrupt state file %s dated %d (now=%d)", 
			statefile, (int)filetime, (int)xfrd_time());
		fclose(in);
		return;
	}
	for(i=0; i<numzones; i++)
	{
		char *p;
		xfrd_zone_t* zone;
		const dname_type* dname;
		uint32_t state, nextmas, timeout;
		xfrd_soa_t soa_nsd_read, soa_disk_read, soa_notified_read;
		time_t soa_nsd_acquired_read, 
			soa_disk_acquired_read, soa_notified_acquired_read;
		memset(&soa_nsd_read, 0, sizeof(soa_nsd_read));
		memset(&soa_disk_read, 0, sizeof(soa_disk_read));
		memset(&soa_notified_read, 0, sizeof(soa_notified_read));

		if(!xfrd_read_check_str(in, "zone:") ||
		   !xfrd_read_check_str(in, "name:")  ||
		   !(p=xfrd_read_token(in)) ||
		   !(dname = dname_parse(tempregion, p))
		)
		{
			log_msg(LOG_ERR, "xfrd: corrupt state file %s dated %d (now=%d)", 
				statefile, (int)filetime, (int)xfrd_time());
			fclose(in);
			return;
		}
		zone = (xfrd_zone_t*)rbtree_search(xfrd->zones, dname);
		if(!zone) {
			log_msg(LOG_INFO, "xfrd: state file has info for not configured zone %s", p);
			p="";
			while(strcmp(p, "#endzone") != 0)
				if(!(p=xfrd_read_token(in))) {
					log_msg(LOG_ERR, "xfrd: corrupt state file %s dated %d (now=%d)", 
						statefile, (int)filetime, (int)xfrd_time());
					fclose(in);
					return;
				}
			continue;
		}
		if(!xfrd_read_check_str(in, "state:") ||
		   !xfrd_read_i32(in, &state) || (state>2) ||
		   !xfrd_read_check_str(in, "next_master:") ||
		   !xfrd_read_i32(in, &nextmas) ||
		   !xfrd_read_check_str(in, "next_timeout:") ||
		   !xfrd_read_i32(in, &timeout) ||
		   !xfrd_read_state_soa(in, "soa_nsd_acquired:", "soa_nsd:",
			&soa_nsd_read, &soa_nsd_acquired_read, tempregion) ||
		   !xfrd_read_state_soa(in, "soa_disk_acquired:", "soa_disk:",
			&soa_disk_read, &soa_disk_acquired_read, tempregion) ||
		   !xfrd_read_state_soa(in, "soa_notified_acquired:", "soa_notified:",
			&soa_notified_read, &soa_notified_acquired_read, tempregion) ||
		   !xfrd_read_check_str(in, "#endzone")
		)
		{
			log_msg(LOG_ERR, "xfrd: corrupt state file %s dated %d (now=%d)", 
				statefile, (int)filetime, (int)xfrd_time());
			fclose(in);
			return;
		}
		zone->zone_state = state;
		zone->next_master_num = nextmas;
		zone->timeout.tv_sec = timeout;
		zone->timeout.tv_nsec = 0;

		/* read the zone OK, now set the master and timeout properly */
		/* copy nsdsoa disksoa notifiedsoa to memstruct, perhaps */
	}

	if(!xfrd_read_check_str(in, XFRD_FILE_MAGIC)) {
		log_msg(LOG_ERR, "xfrd: corrupt state file %s dated %d (now=%d)", 
			statefile, (int)filetime, (int)xfrd_time());
		fclose(in);
		return;
	}
	
	log_msg(LOG_INFO, "xfrd: read %d zones from state file", numzones);
	fclose(in);
	region_destroy(tempregion);
}

/* prints neato days hours and minutes. */
static void neato_timeout(FILE* out, const char* str, uint32_t secs)
{
	fprintf(out, "%s", str);
	if(secs <= 0) {
		fprintf(out, " %ds\n", secs);
		return;
	}
	if(secs >= 3600*24) {
		fprintf(out, " %dd", secs/(3600*24));
		secs = secs % (3600*24);
	}
	if(secs >= 3600) {
		fprintf(out, " %dh", secs/3600);
		secs = secs%3600;
	}
	if(secs >= 60) {
		fprintf(out, " %dm", secs/60);
		secs = secs%60;
	}
	if(secs > 0) {
		fprintf(out, " %ds", secs);
	}
}

static void xfrd_write_state_soa(FILE* out, const char* id,
	xfrd_soa_t* soa, time_t soatime, const dname_type* apex)
{
	fprintf(out, "\t%s_acquired: %d\n", id, (int)soatime);
	if(!soatime) return;
	fprintf(out, "\t%s: %d %d %d %d", id, 
		ntohs(soa->type), ntohs(soa->klass), 
		ntohl(soa->ttl), ntohs(soa->rdata_count));
	fprintf(out, " %s", dname_to_string(soa->prim_ns, apex));
	fprintf(out, " %s", dname_to_string(soa->email, apex));
	fprintf(out, " %d", ntohl(soa->serial));
	fprintf(out, " %d", ntohl(soa->refresh));
	fprintf(out, " %d", ntohl(soa->retry));
	fprintf(out, " %d", ntohl(soa->expire));
	fprintf(out, " %d\n", ntohl(soa->minimum));
	fprintf(out, "\t#");
	neato_timeout(out, " refresh =", ntohl(soa->refresh));
	neato_timeout(out, " retry =", ntohl(soa->retry));
	neato_timeout(out, " expire =", ntohl(soa->expire));
	neato_timeout(out, " minimum =", ntohl(soa->minimum));
	fprintf(out, "\n");
}

static void xfrd_write_state()
{
	rbnode_t* p;
	const char* statefile = xfrd->nsd->options->xfrdfile;
	FILE *out;
	if(!statefile) statefile = "nsd.xfrdstate";

	log_msg(LOG_INFO, "xfrd: write file %s", statefile);
	out = fopen(statefile, "w");
	if(!out) {
		log_msg(LOG_ERR, "xfrd: Could not open file %s for writing: %s",
				statefile, strerror(errno));
		return;
	}
	
	fprintf(out, "%s\n", XFRD_FILE_MAGIC);
	fprintf(out, "filetime: %d\n", (int)xfrd_time());
	fprintf(out, "numzones: %d\n", (int)xfrd->zones->count);
	fprintf(out, "\n");
	for(p = rbtree_first(xfrd->zones); p && p!=RBTREE_NULL; p=rbtree_next(p))
	{
		xfrd_zone_t* zone = (xfrd_zone_t*)p;
		fprintf(out, "zone: \tname: %s\n", zone->apex_str);
		fprintf(out, "\tstate: %d", zone->zone_state);
		fprintf(out, " # %s", zone->zone_state==xfrd_zone_ok?"OK":(
			zone->zone_state==xfrd_zone_refreshing?"refreshing":"expired"));
		fprintf(out, "\n");
		fprintf(out, "\tnext_master: %d\n", zone->next_master_num);
		fprintf(out, "\tnext_timeout: %d", 
			zone->zone_handler.timeout?(int)zone->timeout.tv_sec:0);
		if(zone->zone_handler.timeout) {
			neato_timeout(out, "\t# =", zone->timeout.tv_sec - xfrd_time()); 
		}
		fprintf(out, "\n");
		xfrd_write_state_soa(out, "soa_nsd", &zone->soa_nsd, 
			zone->soa_nsd_acquired, zone->apex);
		xfrd_write_state_soa(out, "soa_disk", &zone->soa_disk, 
			zone->soa_disk_acquired, zone->apex);
		xfrd_write_state_soa(out, "soa_notify", &zone->soa_notified, 
			zone->soa_notified_acquired, zone->apex);
		fprintf(out, "#endzone\n\n");
	}

	fprintf(out, "%s\n", XFRD_FILE_MAGIC);
	fclose(out);
}