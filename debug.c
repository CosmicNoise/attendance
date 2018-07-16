#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>
#include <string.h>

#include "config.h"
#include "debug.h"

/** @internal
  Do not use directly, use the debug macro */
	void
_debug(const char *filename, int line, int level, const char *format, ...)
{
	char buf[28];
	va_list vlist;
	config_t *config = config_get_config();
	time_t ts;

	time(&ts);
	if (config->log_level >= level) {
		if (level <= LOG_WARNING) {
			fprintf(stderr, "[%d][%.24s][%u](%s:%d) ", level, ctime_r(&ts, buf), getpid(),
					filename, line);
			va_start(vlist, format);
			vfprintf(stderr, format, vlist);
			va_end(vlist);
			fputc('\n', stderr);
		}
		if(config->log_level >= LOG_DEBUG){
			fprintf(stdout, "[%d][%.24s][%u](%s:%d) ", level, ctime_r(&ts, buf), getpid(),
					filename, line);
			va_start(vlist, format);
			vfprintf(stdout, format, vlist);
			va_end(vlist);
			fputc('\n', stdout);
			fflush(stdout);
		}
		if (config->log_syslog) {
			openlog("sniffer", LOG_PID, LOG_DAEMON);
			va_start(vlist, format);
			vsyslog(level, format, vlist);
			va_end(vlist);
			closelog();
		}
	}
}


