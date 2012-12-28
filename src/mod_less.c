/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_script.h"
#include "http_connection.h"

#include "apr_strings.h"

#include <stdio.h>

#define MAX_ERROR_SIZE 2*1024

int send_css_file(const char *filename, const apr_size_t size, request_rec *r) {
	apr_status_t status;
	apr_file_t *fd;
	apr_size_t sentbytes;

	// open...
	status = apr_file_open(&fd, filename, APR_READ | APR_BUFFERED | APR_SENDFILE_ENABLED, APR_OS_DEFAULT, r->pool);
	if(status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_file_open failed while opening %s for read", filename);
		return 0;
	}

	// ...send...
	ap_set_content_type(r, "text/css");
	status = ap_send_fd(fd, r, 0, size, &sentbytes);
	if(status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "ap_send_fd failed while sending %s", filename);
		return 0;
	}

	// ...and close
	status = apr_file_close(fd);
	if(status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_file_close failed while closing %s", filename);
		return 0;
	}

	return 1;
}

int close_and_delete(apr_file_t *fd, const char* file, request_rec *r) {
	apr_status_t status;

	status = apr_file_close(fd);
	if(status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_file_close failed while closing %s", file);
		return 0;
	}

	status = apr_file_remove(file, r->pool);
	if(status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_file_remove failed while removing %s", file);
		return 0;
	}

	return 1;
}

static int less_handler(request_rec* r) {
	if (!r->handler || strcmp(r->handler, "less"))
		return DECLINED;

	if (r->method_number != M_GET)
		return HTTP_METHOD_NOT_ALLOWED;

	apr_status_t status;

	// strip the extension of the filename in the request.
	//   r->filename=foo.css or foo.less -> basename=foo
	char *basename = strdup(r->filename);
	if(basename == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "strdup returned NULL while building the files' basename");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	// find the last dot
	char *pextension = strrchr(basename, '.');

	// no dot found -> the filename is already the basename
	if(pextension == NULL) {
		pextension = basename;
	}
	else {
		*pextension = '\0';
	}

	// build the paths to three files (css, less and tmp)
	//  cssfile=foo.css, lessfile=foo.less
	char *cssfile;
	char *lessfile;
	char *tmpfile;
	if(asprintf(&lessfile, "%s.less", basename) == -1) {
		free(basename);
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "asprintf failed while formatting the less-filename");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	if(asprintf(&cssfile, "%s.css", basename) == -1) {
		free(basename);
		free(lessfile);
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "asprintf failed while formatting the css-filename");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	if(asprintf(&tmpfile, "%s.css.tmpXXXXXX", basename) == -1) {
		free(basename);
		free(lessfile);
		free(cssfile);
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "asprintf failed while formatting the tmp-filename");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	free(basename);

	apr_finfo_t lessinfo;
	apr_finfo_t cssinfo;

	// try to get the stat of the less-file. If it fails, there is no less-file.
	// if there is no less-file corresponding to this css-file,
	// it's probably a simple standalone css-file and should
	// not be handled by this module
	if(apr_stat(&lessinfo, lessfile, APR_FINFO_MTIME, r->pool) != APR_SUCCESS) {
		free(lessfile);
		free(cssfile);
		return DECLINED;
	}

	// try to get the stat of the compiled css-file. If it succeeds, there is an already compiled-file.
	// if there is a corresponding less-file and an already compiled
	// css-file, stat them both and see, if the css-file is recent enough
	if(apr_stat(&cssinfo, cssfile, APR_FINFO_MTIME | APR_FINFO_SIZE, r->pool) == APR_SUCCESS) {

		// check, if the css-file is up-to-date
		if(cssinfo.mtime > lessinfo.mtime) {

			// send the css-file
			if(!send_css_file(cssfile, cssinfo.size, r)) {
				free(lessfile);
				free(cssfile);
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			// and we're done here
			free(lessfile);
			free(cssfile);
			return OK;
		}

	}

	// either there is not css-file or it is to old - in any way, we need to re-compile it
	ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Compiling CSS-File %s from LESS-File %s via TMP-File %s", cssfile, lessfile, tmpfile);

	// create the temp-file
	apr_file_t *tmpfd;
	status = apr_file_mktemp(&tmpfd, tmpfile, APR_CREATE | APR_READ | APR_WRITE | APR_EXCL, r->pool);
	if(status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_file_mktemp failed while creating the temp-file: %s", tmpfile);

		free(lessfile);
		free(cssfile);
		free(tmpfile);
		return HTTP_INTERNAL_SERVER_ERROR;
	}


	// TODO: place to config
	//  placing the STDERR redirection before the STDOUT redirection gives us a
	//  not-so-obvious result: sh connects lessc's STDERR with the popen-stream
	//  and lessc's STDOUT with the named file - we get the errors and not the css-code
	const char* lessc = "lessc --no-color %s 2>&1 >%s";

	// construct the command to run
	char* cmd;
	if(asprintf(&cmd, lessc, lessfile, tmpfile) == -1) {
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "asprintf failed while constructing the lessc-command out of %s, %s and %s", lessc, lessfile, cssfile);

		close_and_delete(tmpfd, tmpfile, r);
		free(lessfile);
		free(cssfile);
		free(tmpfile);

		return HTTP_INTERNAL_SERVER_ERROR;
	}

	// execute lessc
	//  this pipes the generated css-code into the tmpfile and the error into our popen-pipe
	//  if the command succeeds, we'll move the tmpfile over the original css-file,
	//  when lessc reports an error the tmpfile is meaningless and gets deleteds
	//  TODO: error check
	char err[MAX_ERROR_SIZE];
	FILE* pp = popen(cmd, "r");
	size_t bytes_read = fread(&err, 1, MAX_ERROR_SIZE-1, pp);
	err[bytes_read] = '\0';
	int ret = pclose(pp);

	// check if lessc returned an error
	if(ret != 0) {
		ap_set_content_type(r, "text/plain");
		ap_rputs(err, r);

		ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "lessc command '%s' returned %i, reporting '%s'", cmd, ret, err);

		// close and delete the tmpfile
		if(!close_and_delete(tmpfd, tmpfile, r))
			return HTTP_INTERNAL_SERVER_ERROR;

		free(lessfile);
		free(cssfile);
		free(tmpfile);
		free(cmd);

		// I would like to send a HTTP_INTERNAL_SERVER_ERROR but then apache ignores
		// the sent error text and instead displays its own
		return OK;
	}
	free(cmd);

	// move the tmpfile over the cssfile
	status = apr_file_rename(tmpfile, cssfile, r->pool);
	if(status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_file_rename failed while moving the tmpfile %s over the cssfile %s", tmpfile, cssfile);

		free(lessfile);
		free(cssfile);
		free(tmpfile);

		return HTTP_INTERNAL_SERVER_ERROR;
	}

	// close the filepointer pointing to the tmpfile
	// this removes the EXCL-lock on the file
	status = apr_file_close(tmpfd);
	if(status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_file_close failed while closing %s", tmpfile);

		free(lessfile);
		free(cssfile);
		free(tmpfile);

		return HTTP_INTERNAL_SERVER_ERROR;
	}

	free(tmpfile);
	free(lessfile);

	// re-stat the css-file to get the new size
	status = apr_stat(&cssinfo, cssfile, APR_FINFO_SIZE, r->pool);
	if(status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_stat failed while stat'ing %s", cssfile);

		free(cssfile);

		return HTTP_INTERNAL_SERVER_ERROR;
	}

	// send the css-file
	if(!send_css_file(cssfile, cssinfo.size, r)) {
		free(cssfile);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	// and we're finally done
	free(cssfile);
	return OK;
}
 
static void register_hooks(apr_pool_t* pool)
{
	ap_hook_handler(less_handler, NULL, NULL, APR_HOOK_MIDDLE);
}
 
module AP_MODULE_DECLARE_DATA less_module = {
	STANDARD20_MODULE_STUFF,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	register_hooks
};
