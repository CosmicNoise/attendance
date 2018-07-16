#ifndef _CONFIG_H_
#define _CONFIG_H_

#define  MAX_BUF 4096
#define PATHSIZE 256

typedef struct {
	/* server address:port and url */
	char *remotehost;
	char *remotepath;
	char *remoteport;

	/* local address:port and url */
	char *localhost;
	char *localport;

	/*  debug level */
	int log_level;
	int log_syslog;

	/* upload interval */
	int interval;

	/* upload interface flow */
	char *macaddr;


} config_t ;

config_t * config_get_config(void);
void parse_arg(int argc, char **argv);

#endif
