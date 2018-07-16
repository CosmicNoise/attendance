#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <features.h>
#include <json-c/json.h>

#include "debug.h"
#include "config.h"

config_t defconfig;

static void usage(void)
{
    printf("Usage: main [options]\n");
    printf("\n");
    printf("  -c [filename] JSON format config file\n");
    printf("  -h            Print usage\n");
    printf("  -v            Print program version\n");
    printf("\n");
}

config_t * config_get_config(void)
{
	    return &defconfig;
}


void config_init(json_object *obj)
{
	int full = 0;
	json_object_object_foreach(obj, key, val){
		if(!strcasecmp(key, "loglevel")){
			defconfig.log_level = json_object_get_int(val);
		}
		else if(!strcasecmp(key, "remotehost")) {
			defconfig.remotehost = strdup(json_object_get_string(val));	
			full++;
		}
		else if(!strcasecmp(key, "remotepath")) {
			defconfig.remotepath = strdup(json_object_get_string(val));
			full++;
		}
		else if(!strcasecmp(key, "remoteport")) {
			defconfig.remoteport = strdup(json_object_get_string(val));
			full++;
		}
		else if(!strcasecmp(key, "localhost")){
			defconfig.localhost = strdup(json_object_get_string(val));	
			full++;
		}
		else if(!strcasecmp(key, "localport")){
			defconfig.localport = strdup(json_object_get_string(val));
			full++;
		}
		else if(!strcasecmp(key, "syslog")){
			defconfig.log_syslog = json_object_get_int(val);
		}
		else if(!strcasecmp(key, "macaddr")){
			defconfig.macaddr = strdup(json_object_get_string(val));
			full++;
		}
		else if(!strcasecmp(key, "interval")){
			defconfig.interval = json_object_get_int(val);
			full++;
		}
	}
	if(full < 6){
		printf("Parameter missing, please check config file\n");
		exit(1);
	}
	return;
}

void parse_arg(int argc, char **argv)
{
    int c;
	int skiponrestart;
	int done = 0;

    config_t *config = config_get_config();

    while (-1 != (c = getopt(argc, argv, "c:hv"))) {
		switch(c) {
			case 'h':{
				usage();
				exit(1);
				break;
			}
			case 'c':{
				if (optarg) {
					json_object *obj = json_object_from_file(optarg);
					if(obj) {
						config_init(obj);	
						done = 1;
						json_object_put(obj);
					}
					else {
						printf("resolve config error\n");	
						exit(1);
					}
				}
				break;
			}
			case 'v':{
				printf("Version 1.0.0d\n");
				exit(1);
				break;
			}
			default:{
				usage();
				exit(1);
				break;
			}
		}
	}
	if(!done) {
		printf("Parameter missing, please check config file\n");
		exit(1);
	}
}

