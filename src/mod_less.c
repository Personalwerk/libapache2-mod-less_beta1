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
#include <string>
#include <stdexcept>
#include <fstream>

#define MAX_ERROR_SIZE 2*1024
#define MAX_INPUT_SIZE 1024

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(less);
#endif

typedef struct {
	int compress;
	int relative_urls;
	int recompile;
	int map_file;
} mod_less_cfg;

// forward declarations
static void *create_mod_less_config(apr_pool_t* pool, server_rec* srv);
static void *merge_server_config(apr_pool_t* pool, void* basev, void* addv);

static const char * take_recompile(cmd_parms * parms, void *mconfig, const char *arg);
static const char * toggle_relative_urls(cmd_parms * parms, void *mconfig, int flag);
static const char * toggle_less_compression(cmd_parms * parms, void *mconfig, int flag);
static const char * toggle_map_file(cmd_parms * parms, void *mconfig, int flag);

static const command_rec mod_less_commands[] = {
	AP_INIT_FLAG("LessRelativeUrls", (cmd_func)toggle_relative_urls, NULL, OR_ALL, "Compile less files with the --relative-urls flag."),
	AP_INIT_FLAG("LessCompress", (cmd_func)toggle_less_compression, NULL, OR_ALL, "Compile less files with the --compress flag."),
	AP_INIT_TAKE1("LessRecompile", (cmd_func)take_recompile, NULL, OR_ALL, "Recompile less files, Always, Mtime or Auto"),
	AP_INIT_FLAG("LessMapFile", (cmd_func)toggle_map_file, NULL, OR_ALL, "Compile less files with --source-map-less-inline and --source-map-map-inline."),
	{ NULL }
};

static void register_hooks(apr_pool_t* pool);

module AP_MODULE_DECLARE_DATA less_module = {
	STANDARD20_MODULE_STUFF,
	NULL,
	NULL,
	create_mod_less_config, // per-server config
	merge_server_config,
	mod_less_commands,
	register_hooks
};

static const char * take_recompile(cmd_parms * parms, void *mconfig, const char *arg) {
	mod_less_cfg * cfg = (mod_less_cfg *)ap_get_module_config(parms->server->module_config, &less_module);
	if (strcmp(arg, "Always") == 0)
		cfg->recompile = 1;
	else if (strcmp(arg, "Auto") == 0)
		cfg->recompile = 0;
	else
		cfg->recompile = -1;
	return NULL;
}

static const char * toggle_relative_urls(cmd_parms * parms, void *mconfig, int flag) {
	mod_less_cfg * cfg = (mod_less_cfg *)ap_get_module_config(parms->server->module_config, &less_module);
	cfg->relative_urls = flag;
	return NULL;
}

static const char * toggle_less_compression(cmd_parms * parms, void *mconfig, int flag) {
	mod_less_cfg * cfg = (mod_less_cfg *)ap_get_module_config(parms->server->module_config, &less_module);
	cfg->compress = flag;
	return NULL;
}

static const char * toggle_map_file(cmd_parms * parms, void *mconfig, int flag) {
	mod_less_cfg * cfg = (mod_less_cfg *)ap_get_module_config(parms->server->module_config, &less_module);
	cfg->map_file = flag;
	return NULL;
}

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

	try {

		// strip the extension from the filename in the request.
		//   r->filename=foo.css or foo.less -> basename=foo
		std::string filename(r->filename);

		std::string basename = filename.substr(0, filename.find_last_of("."));

		std::string cssfile(basename);
		std::string lessfile(basename);
		std::string depfile(basename);
		std::string csstmpfile(basename);
		std::string deptmpfile(basename);
		std::string errtmpfile(basename);

		cssfile.append(".css");
		lessfile.append(".less");
		depfile.append(".dep");
		csstmpfile.append(".css.tmpXXXXXX");
		deptmpfile.append(".dep.tmpXXXXXX");
		errtmpfile.append(".err.tmpXXXXXX");


		apr_finfo_t lessinfo;
		apr_finfo_t cssinfo;

		mod_less_cfg * cfg = NULL;
		cfg = (mod_less_cfg *) ap_get_module_config(r->server->module_config, &less_module);

		// try to get the stat of the less file. If it fails, there is no less file.
		// if there is no less file corresponding to this css file,
		// it's probably a simple standalone css file and should
		// not be handled by this module
		if(apr_stat(&lessinfo, lessfile.c_str(), APR_FINFO_MTIME, r->pool) != APR_SUCCESS) {
			return DECLINED;
		}

		// try to get the stat of the compiled css file. If it succeeds, there is an already-compiled file.
		// if there is a corresponding less file and an already-compiled css file,
		// stat them both and see if the css file is recent enough to satisfy the request
		if(apr_stat(&cssinfo, cssfile.c_str(), APR_FINFO_MTIME | APR_FINFO_SIZE, r->pool) == APR_SUCCESS) {
			// check, if the css-file is up-to-date
			if (cfg->recompile < 0 && cssinfo.mtime > lessinfo.mtime) {

				// send the css-file
				if(!send_css_file(cssfile.c_str(), cssinfo.size, r)) {
					return HTTP_INTERNAL_SERVER_ERROR;
				}

				// and we're done here
				return OK;
			}
			// check, if css-file is up-to-date and auto recompile is active
			if (cfg->recompile == 0 && cssinfo.mtime > lessinfo.mtime) {

				bool recompile = false;
				std::ifstream ifs (depfile.c_str(), std::ifstream::in);

				if (!ifs.fail()) {
					while (!ifs.eof()) {
						std::string ifsfilename;
						std::getline (ifs, ifsfilename, ' ');	

						// Check if ifsfilename ends with ':', this is the first output in the .dep file and can be ignored
						if ((ifsfilename.compare(ifsfilename.length()-1, 1, ":") == 0) || (ifsfilename.compare("\n") == 0))
							continue;
						
						apr_finfo_t depinfo;
						
						// If a file in the dep-file doesn't exist, break - we should better recompile
						if (apr_stat(&depinfo, ifsfilename.c_str(), APR_FINFO_MTIME, r->pool) != APR_SUCCESS) {
							recompile = true;
							ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Couldn't stat %s - recompiling.", ifsfilename.c_str());
							break;
						}

						// If a file in the dep-file is newer than the css - we should recompile
						if (depinfo.mtime > cssinfo.mtime) {
							recompile = true;
							ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "File: %s is newer than css file - recompiling", ifsfilename.c_str());
							break;
						}
					}
				} else {
					ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "No dependency file found (%s) - recompiling", depfile.c_str());
					recompile = true;
				}

				if (!recompile) {

					// send the css-file
					if(!send_css_file(cssfile.c_str(), cssinfo.size, r)) {
						return HTTP_INTERNAL_SERVER_ERROR;
					}

					// and we're done here
					return OK;
				}
			}
		}


		std::string lessc_flags("");

		if (cfg->relative_urls == 1) {
			lessc_flags.append(" --relative-urls");
		}
		if (cfg->compress == 1) {
			lessc_flags.append(" --compress");
		}
		if (cfg->recompile == 0) {
			lessc_flags.append(" --depends");
		}
		if (cfg->map_file == 1) {
			lessc_flags.append(" --source-map")
				.append(" --source-map-less-inline");
		}
		lessc_flags.append(" ");
		
		// either there is no css file or it is too old - either way we need to recompile it
		ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "Compiling CSS File %s from LESS File %s via TMP File %s with flags %s", cssfile.c_str(), lessfile.c_str(), csstmpfile.c_str(), lessc_flags.c_str());

		// create the temp file
		apr_file_t *csstmpfd;
		status = apr_file_mktemp(&csstmpfd, const_cast<char*>(csstmpfile.c_str()), APR_CREATE | APR_READ | APR_WRITE | APR_EXCL, r->pool);
		if(status != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_file_mktemp failed while creating the temp file: %s", csstmpfile.c_str());

			return HTTP_INTERNAL_SERVER_ERROR;
		}

		// create the temp file
		apr_file_t *errtmpfd;
		status = apr_file_mktemp(&errtmpfd, const_cast<char*>(errtmpfile.c_str()), APR_CREATE | APR_READ | APR_WRITE | APR_EXCL, r->pool);
		if(status != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_file_mktemp failed while creating the temp file: %s", errtmpfile.c_str());

			return HTTP_INTERNAL_SERVER_ERROR;
		}

		apr_file_t *deptmpfd;
		if (cfg->recompile == 0) {
			// create the temp file
			status = apr_file_mktemp(&deptmpfd, const_cast<char*>(deptmpfile.c_str()), APR_CREATE | APR_READ | APR_WRITE | APR_EXCL, r->pool);
			if(status != APR_SUCCESS) {
				ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_file_mktemp failed while creating the temp file: %s", deptmpfile.c_str());

				return HTTP_INTERNAL_SERVER_ERROR;
			}		
		}


		// TODO: place to config
		//  placing the STDERR redirection before the STDOUT redirection gives us a
		//  not-so-obvious result: sh connects lessc's STDERR with the popen stream
		//  and lessc's STDOUT with the named file - we get the errors and not the css code
		std::string cmd("lessc --no-color");
		cmd.append(lessc_flags)
			.append(lessfile)
			.append(" ")
			.append(csstmpfile.c_str())
			.append(" 2>")
			.append(errtmpfile.c_str())
			.append(" >");
		if (cfg->recompile == 0) {
			cmd.append(deptmpfile.c_str());
		} else {
			cmd.append("/dev/null");
		}

		// execute lessc
		//  if the command succeeds, we'll move the csstmpfile over the original css file,
		//  and - if the option is set - the deptmpfile over the dep file
		//  when lessc reports an error the errtmpfile is moved over the original css file
		int ret = system(cmd.c_str());

		// check if lessc returned an error
		if(ret != 0) {
			ap_set_content_type(r, "text/plain");

			ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "lessc command '%s' returned %i", cmd.c_str(), ret);

			// close and delete the csstmpfile
			if(!close_and_delete(csstmpfd, csstmpfile.c_str(), r))
				return HTTP_INTERNAL_SERVER_ERROR;

			if (cfg->recompile == 0) {
				// close and delete the deptmpfile
				if(!close_and_delete(deptmpfd, deptmpfile.c_str(), r))
					return HTTP_INTERNAL_SERVER_ERROR;
			}

			// close the filepointer pointing to the errtmpfile
			// this removes the EXCL lock on the file
			status = apr_file_close(errtmpfd);
			if(status != APR_SUCCESS) {
				ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_file_close failed while closing %s", errtmpfile.c_str());

				return HTTP_INTERNAL_SERVER_ERROR;
			}

			// move the errtmpfile over the cssfile
			status = apr_file_rename(errtmpfile.c_str(), cssfile.c_str(), r->pool);
			if(status != APR_SUCCESS) {
				ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_file_rename failed while moving the err tmpfile %s over the cssfile %s", errtmpfile.c_str(), cssfile.c_str());

				return HTTP_INTERNAL_SERVER_ERROR;
			}
		

			// I would like to send a HTTP_INTERNAL_SERVER_ERROR but apache ignores
			// the sent error text and instead displays its own
			return OK;
		}

		// close and delete the errtmpfile
		if(!close_and_delete(errtmpfd, errtmpfile.c_str(), r))
			return HTTP_INTERNAL_SERVER_ERROR;

		// close the filepointer pointing to the csstmpfile
		// this removes the EXCL lock on the file
		status = apr_file_close(csstmpfd);
		if(status != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_file_close failed while closing %s", csstmpfile.c_str());

			return HTTP_INTERNAL_SERVER_ERROR;
		}

		// move the csstmpfile over the cssfile
		status = apr_file_rename(csstmpfile.c_str(), cssfile.c_str(), r->pool);
		if(status != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_file_rename failed while moving the css tmpfile %s over the cssfile %s", csstmpfile.c_str(), cssfile.c_str());

			return HTTP_INTERNAL_SERVER_ERROR;
		}

		if (cfg->recompile == 0) {
			// close the filepointer pointing to the deptmpfile
			// this removes the EXCL lock on the file
			status = apr_file_close(deptmpfd);
			if(status != APR_SUCCESS) {
				ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_file_close failed while closing %s", deptmpfile.c_str());

				return HTTP_INTERNAL_SERVER_ERROR;
			}

			// move the deptmpfile over the depfile
			status = apr_file_rename(deptmpfile.c_str(), depfile.c_str(), r->pool);
			if(status != APR_SUCCESS) {
				ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_file_rename failed while moving the dep tmpfile %s over the depfile %s", deptmpfile.c_str(), depfile.c_str());

				return HTTP_INTERNAL_SERVER_ERROR;
			}
		}

		// re-stat the css file to get the new size
		status = apr_stat(&cssinfo, cssfile.c_str(), APR_FINFO_SIZE, r->pool);
		if(status != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r, "apr_stat failed while stat'ing %s", cssfile.c_str());

			return HTTP_INTERNAL_SERVER_ERROR;
		}


		// send the css file
		if(!send_css_file(cssfile.c_str(), cssinfo.size, r)) {
			return HTTP_INTERNAL_SERVER_ERROR;
		}


		// and we're finally done
		return OK;

	}
	catch (const std::length_error& le) {
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Caught internal 'length_error' exception: %s", le.what());
	}
	catch (const std::bad_alloc& ba) {
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Caught internal 'bad_alloc' exception: %s", ba.what());
	}
	catch (const std::out_of_range& oor) {
		ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Caught internal 'out_of_range' exception: %s", oor.what());
	}
	return HTTP_INTERNAL_SERVER_ERROR;
}
 
static void *create_mod_less_config(apr_pool_t* pool, server_rec* srv) {
	mod_less_cfg * cfg;

	cfg = (mod_less_cfg*) apr_pcalloc(pool, sizeof(mod_less_cfg));

	cfg->compress = 0;
	cfg->relative_urls = 1;
	cfg->recompile = -1;
	cfg->map_file = 1;

	return (void *) cfg;
}

static void *merge_server_config(apr_pool_t* pool, void* basev, void* addv) {
	mod_less_cfg *base = (mod_less_cfg *)basev;
	mod_less_cfg *add = (mod_less_cfg *)addv;
	mod_less_cfg *mrg = (mod_less_cfg *)apr_pcalloc(pool, sizeof(mod_less_cfg));

	mrg->compress = add->compress;
	mrg->relative_urls = add->relative_urls;
	mrg->recompile = add->recompile;
	mrg->map_file = add->map_file;
	return (void *)mrg;
}

static void register_hooks(apr_pool_t* pool)
{
	ap_hook_handler(less_handler, NULL, NULL, APR_HOOK_MIDDLE);
}
