#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>  
#include <syslog.h>
#include <ctype.h>

#include <libev/ev.h>
#include <json-c/json.h>

#include "usock.h"
#include "ringbuffer.h"
#include "debug.h"
#include "config.h"

struct ev_io sniffer;
struct ev_timer upload;
config_t defconfig;
RingBuffer *rb;

struct sniffer_ctx {
	struct ev_io out;
	struct ev_io in;
	struct ev_timer watcher;
	char *data;
	char *origin;
	int data_len;
	int fd;
	int connected;
};

/* Return a pointer to a @c struct, given a pointer to one of its
    * fields. */
#define container_of(field, struct_type, field_name) \
	    ((struct_type *) (- offsetof(struct_type, field_name) + \
			                      (void *) (field)))


int32_t isValidMac(const int8_t *mac)
{
	int8_t *reg="^([0-9a-fA-F]{2})(([/\\s:][0-9a-fA-F]{2}){5})$";
	regex_t pat_cmdline;
	regmatch_t matches[17];
	if(regcomp(&pat_cmdline, reg, REG_EXTENDED)){
		debug(LOG_DEBUG,"regcomp error <%s>\n", strerror(errno));        
		return -1;
	}   
	if(regexec(&pat_cmdline, mac, 17, matches, 0)){
		regfree(&pat_cmdline);  
		return -1; 
	}   
	regfree(&pat_cmdline);
	return 0;
}

char* str_tolower(char *str)
{
	char *c; 
    for (c = str; *c; ++c) {
        *c = tolower(*c);
	}
    return str;
}


void local_recv_cb(EV_P_ ev_io *io, int e)
{
	char buf[10240];
	int retlen = 0;
	char ts_str[12];
	time_t ts;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	retlen = recvfrom(io->fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addrlen);
	if(retlen < 0){
		debug(LOG_DEBUG,"recvfrom:%s", strerror(errno));
		return;
	}
	sendto(io->fd, "1", 1, 0, (struct sockaddr *)&addr, addrlen);
	debug(LOG_DEBUG,"sendto:%s\n", strerror(errno));
	debug(LOG_DEBUG,"recieve:\n%s\n", buf);
	RingBuffer_write(rb, "#\n", 2);
	ts = time(NULL);
	if(sprintf(ts_str, "%d\n", ts) < 0){
		debug(LOG_DEBUG,"set timestamp error:%s\n", strerror(errno));
	}
	RingBuffer_write(rb, ts_str, 11);	

	if(retlen != RingBuffer_write(rb, str_tolower(buf), retlen)){
		debug(LOG_DEBUG,"write ringbuffer error\n");
		return;
	}

	debug(LOG_DEBUG,"timestamp:%s\n", ts_str);
	debug(LOG_DEBUG,"write %d to ringbuffer\n", retlen);
	return;
}

static void free_remote(struct sniffer_ctx *ctx)
{
	ev_timer_stop(EV_DEFAULT, &ctx->watcher);
	ev_io_stop(EV_DEFAULT, &ctx->out);
	ev_io_stop(EV_DEFAULT, &ctx->in);
	close(ctx->fd);
	free(ctx->origin);
	free(ctx);
	return;	
}

static void remote_recv_cb(EV_P_ ev_io *w, int revents)
{
	struct sniffer_ctx *tmp = container_of(w, struct sniffer_ctx, in);
	int ret;
	char buf[10240];

	ret = recv(tmp->fd, buf, 10240, 0);
	if (ret == 0){
		/* connection closed */
		debug(LOG_DEBUG,"connection closed\n");
		free_remote(tmp);
		return;
	}
	else if(ret == -1){
		if (errno == EAGAIN || errno == EWOULDBLOCK) { 
			// continue to wait for recv 
			debug(LOG_DEBUG,"receive nothing, wait for the next time to receive\n");
			return;
		}
		else {
			free_remote(tmp);
			debug(LOG_DEBUG,"receive error:%s\n", strerror(errno));
			return;
		}
	}
	else {
		debug(LOG_DEBUG,"server response:%s\n", buf);
		return;
	}
}

static void remote_send_cb(EV_P_ ev_io *w, int revents)
{
	struct sniffer_ctx *tmp = container_of(w, struct sniffer_ctx, out);
	int ret;
	ret = send(tmp->fd, tmp->data, tmp->data_len, 0);
	if(ret == -1){
		/* wait for send */
		if(errno == EAGAIN || errno == EWOULDBLOCK){
			debug(LOG_DEBUG,"send again\n");
			return;
		}	
		else {
			debug(LOG_DEBUG,"send error:%s\n", strerror(errno));
			free_remote(tmp);
			return;
		}
	}
	else if (ret < tmp->data_len){
		debug(LOG_DEBUG, "has sent %d, remain %d\n", ret, tmp->data_len - ret);
		/* wait for the next time to send */
		tmp->data +=ret;
		tmp->data_len -= ret;
	}
	else {
		debug(LOG_DEBUG, "all sent out, wait for reading");
		/* all sent out, wait for reading */
		ev_io_stop(EV_DEFAULT, &tmp->out);
		ev_io_start(EV_DEFAULT, &tmp->in);
		ev_timer_start(EV_DEFAULT, &tmp->watcher);
	}
	return;
}

static void remote_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
	struct sniffer_ctx *tmp = container_of(watcher, struct sniffer_ctx, watcher);
	free_remote(tmp);
	return;
}

int new_remote(const char *content)
{
	int sockfd;
	char *buf;
	int ret;
	struct sniffer_ctx *ctx;
	config_t *config = config_get_config();
	sockfd = usock(USOCK_TCP | USOCK_NONBLOCK, config->remotehost, config->remoteport);
	if(sockfd < 0){
		debug(LOG_DEBUG,"create upload socket error:%s\n", strerror(errno));
		return -1;
	}

	ret = asprintf(&buf,  "POST %s%s HTTP/1.0\r\n"
					"User-Agent: Sniffer %s\r\n"
					"Host: %s\r\n"    
					"Content-Length: %d\r\n"
					"Content-Type: application/json;charset:utf-8\r\n"
					"\r\n"
					"%s"
					"\r\n",
					config->remotepath,
					config->macaddr,
					"1.0.0",
					config->remotehost,
					strlen(content),
					content);
	if(ret < 0){
		debug(LOG_DEBUG,"bundle http frame error:%s\n", strerror(errno));
		return ret;
	}

	ctx = (struct sniffer_ctx *)malloc(sizeof(struct sniffer_ctx));
	if(!ctx){
		debug(LOG_DEBUG,"malloc sniffer ctx error:%s\n", strerror(errno));
		return -1;
	}
	ctx->data =	buf;
	ctx->origin = buf;
	ctx->data_len = strlen(buf);
	ctx->fd = sockfd;
	ctx->connected = 0;
	ev_io_init(&ctx->out, remote_send_cb, sockfd, EV_WRITE);
	ev_io_init(&ctx->in, remote_recv_cb, sockfd, EV_READ);
	ev_timer_init(&ctx->watcher, remote_timeout_cb, 75.0, 0.0);
	ev_io_start(EV_DEFAULT, &ctx->out);
	debug(LOG_DEBUG,"http frame:\n%s\n", buf);
//	free(buf);
//	close(sockfd);
}

void sync_timer_cb(EV_P_ ev_timer *w, int e)
{
	int ret;
	char target[10240];
	char *token;
	char *block;
	char *saveptr1;
	char *saveptr2;
	char *ts = NULL;
	char *sniffermac = NULL;
	int ts_flag = 0;
	json_object *jso;
	json_object *submit;
	json_object *setsniffdata;
	json_object *_setsniffdata;
	json_object *sniffdata;
	json_object *_sniffdata;
	json_object *meta;
	json_object *_meta;
	/*
	ret = RingBuffer_read(rb, target, 1024);
	if(ret < 0){
		w->repeat = 30.0;
		ev_timer_again(EV_DEFAULT, w);
		return;
	}
	
	debug(LOG_DEBUG,"read:\n%s\n", target);
	*/
	bstring data;
	if(RingBuffer_available_data(rb) <= 0){
		w->repeat = config_get_config()->interval;
		ev_timer_again(EV_DEFAULT, w);
		return;
	}
	data = RingBuffer_get_all(rb);
	if(!data) {
		debug(LOG_DEBUG,"get all ringbuffer error:%s\n", strerror(errno));
		w->repeat = config_get_config()->interval;
		ev_timer_again(EV_DEFAULT, w);
		return;
	}
	debug(LOG_DEBUG,"all:\n%s\n", data->data);
	debug(LOG_DEBUG,"available data:%d\n", RingBuffer_available_data(rb));
	jso = json_object_new_object();
	submit = json_object_new_object();
	setsniffdata = json_object_new_array();
	_setsniffdata = json_object_new_object();
	sniffdata = json_object_new_array();
	_sniffdata = json_object_new_object();
	meta = json_object_new_array();
	_meta = json_object_new_object();

	token  = strtok_r(data->data, "#", &saveptr1);
	while(token){
		debug(LOG_DEBUG,"token:%s\n", token);
		block = strtok_r(token, "|\n", &saveptr2);
		if(!block) {
			debug(LOG_DEBUG,"error\n");
			goto error;
		}
		ts_flag = 0;
		/* initial timestamp */
		if(!ts){
			ts = block;
			json_object_object_add(_sniffdata, "snifftime", json_object_new_string(ts));
		}
		else if(strcmp(ts, block)) {
			/* update timestamp */
			ts = block;	
			ts_flag = 1;
			json_object_object_add(_sniffdata, "data", meta);
			json_object_array_add(sniffdata, _sniffdata);
			_sniffdata = json_object_new_object();
			json_object_object_add(_sniffdata, "snifftime", json_object_new_string(ts));
			meta = json_object_new_array();
		}

		/* initial sniffer mac */
		block = strtok_r(NULL, "|\n", &saveptr2);
		if(!block){
			debug(LOG_ERR, "error");
			goto error;
		}
		/* initial sniffer mac address */
		if(!sniffermac){
			sniffermac = block;
			json_object_object_add(_setsniffdata, "sniffrouter", json_object_new_string(sniffermac));
		}
		else if(strcmp(sniffermac, block)){
		/* update sniffer mac address */
			sniffermac = block;
			/* new sniffer data */
			if(!ts_flag) {
				json_object_object_add(_sniffdata, "data", meta);
				json_object_array_add(sniffdata,  _sniffdata);
				json_object_object_add(_setsniffdata, "sniffdata", sniffdata);
				json_object_array_add(setsniffdata, _setsniffdata);
			}
			debug(LOG_DEBUG, "setsniffdata:%s\n", json_object_to_json_string(setsniffdata));
			_setsniffdata = json_object_new_object();
			json_object_object_add(_setsniffdata, "sniffrouter", json_object_new_string(sniffermac));
			sniffdata = json_object_new_array();
			if(!ts_flag){
				_sniffdata = json_object_new_object();
				json_object_object_add(_sniffdata, "snifftime", json_object_new_string(ts));
				meta = json_object_new_array();
			}
		}

		while(block){
			/* source MAC address */
			block = strtok_r(NULL, "|\n", &saveptr2);
			if(!block) {
				break;
			}
		//	debug(LOG_DEBUG,"meta:%s\n", block);	
			_meta = json_object_new_object();
			json_object_object_add(_meta, "devmac", json_object_new_string(block));
			/* destination MAC address */
			block = strtok_r(NULL, "|\n", &saveptr2);
			if(!block) {
				json_object_put(_meta);
				break;
			}
		//	debug(LOG_DEBUG,"meta:%s\n", block);	
			json_object_object_add(_meta, "destmac", json_object_new_string(block));
			/* IEEE 802.11 frame type */
			block = strtok_r(NULL, "|\n", &saveptr2);
			if(!block) {
				json_object_put(_meta);
				break;
			}
		//	debug(LOG_DEBUG,"meta:%s\n", block);	
			/* IEEE 802.11 frame subtype */
			block = strtok_r(NULL, "|\n", &saveptr2);
			if(!block) {
				json_object_put(_meta);
				break;
			}
		//	debug(LOG_DEBUG,"meta:%s\n", block);	

			/* IEEE 802.11 frame radio channel */
			block = strtok_r(NULL, "|\n", &saveptr2);
			if(!block) {
				json_object_put(_meta);
				break;
			}
		//	debug(LOG_DEBUG,"meta:%s\n", block);	

			/* IEEE 802.11 frame signal info */
			block = strtok_r(NULL, "|\n", &saveptr2);
			if(!block) {
				json_object_put(_meta);
				break;
			}
			//debug(LOG_DEBUG,"meta:%s\n", block);	
			json_object_object_add(_meta, "signal", json_object_new_string(block));	
			/* unknow data */
			block = strtok_r(NULL, "|\n", &saveptr2);
			if(!block) {
				json_object_put(_meta);
				break;
			}
			//debug(LOG_DEBUG,"meta:%s\n", block);	
			/* unknow data */
			block = strtok_r(NULL, "|\n", &saveptr2);
			if(!block) {
				json_object_put(_meta);
				break;
			}
			json_object_array_add(meta, _meta);
			//debug(LOG_DEBUG,"meta:%s\n", json_object_to_json_string(meta));
		}

		token = strtok_r(NULL, "#", &saveptr1);
	}
	json_object_object_add(_sniffdata, "data", meta);
	json_object_array_add(sniffdata,  _sniffdata);
	json_object_object_add(_setsniffdata, "sniffdata", sniffdata);
	json_object_array_add(setsniffdata, _setsniffdata);
	json_object_object_add(submit, "setsniffdata", setsniffdata);
	json_object_object_add(jso, "submit", submit);

	new_remote(json_object_to_json_string(jso));

error:
	json_object_put(_meta);
	json_object_put(meta);
	json_object_put(_sniffdata);
	json_object_put(sniffdata);
	json_object_put(_setsniffdata);
	json_object_put(setsniffdata);
	json_object_put(submit);
	json_object_put(jso);

	bdestroy(data);
	w->repeat = config_get_config()->interval;
	ev_timer_again(EV_DEFAULT, w);

	return;
}

int main(int argc, char **argv)
{
	int sockfd;
	config_t *config;
	parse_arg(argc, argv);
	config = config_get_config();	
	sockfd = usock(USOCK_UDP |  USOCK_SERVER | USOCK_NONBLOCK, config->localhost, config->localport);
	if(sockfd < 0){
		debug(LOG_DEBUG, "Failed to open %s\n", strerror(errno));
		return -1;
	}

	/* 2M bytes */
	rb = RingBuffer_create(1024 * 1024 * 2);
	if(!rb){
		debug(LOG_DEBUG, "Failed to create ringbuffer:%s\n", strerror(errno));
		return -1;
	}
	debug(LOG_INFO, "Starting");
	ev_io_init(&sniffer, local_recv_cb, sockfd, EV_READ);
	ev_io_start(EV_DEFAULT, &sniffer);
	ev_timer_init(&upload, sync_timer_cb, config->interval, 0.0);
	ev_timer_start(EV_DEFAULT, &upload);
	ev_run(EV_DEFAULT, 0);
	RingBuffer_destroy(rb);
	return 0;
}
