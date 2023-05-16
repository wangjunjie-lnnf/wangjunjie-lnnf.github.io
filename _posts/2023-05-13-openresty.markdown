---
layout: post
title:  "openresty"
date:   2023-05-13 23:22:07 +0000
categories: jekyll
tags: openresty
---

# openresty

## 调试环境设置

### 下载依赖

```shell

# clone源码
git clone https://github.com/openresty/openresty.git

cd openresty

# 下载openresty的所有依赖
make
{
    # 获取nginx版本号
    echo -n "openresty "
    . ./util/ver
    echo

    name=openresty-$version
    # 缓存依赖
    work=$root/work

    # 依赖解压位置
    bundle_dir=$root/$name/bundle
    cd $name/bundle

    # 下载nginx
    ver="$main_ver"
    $root/util/get-tarball "https://openresty.org/download/nginx-$ver.tar.gz" -O nginx-$ver.tar.gz || exit 1
    tar -xzf nginx-$ver.tar.gz || exit 1

    # 针对不同版本nginx的各种patch

    # 下载其他依赖
    ver=0.62
    $root/util/get-tarball "https://github.com/openresty/echo-nginx-module/tarball/v$ver" -O echo-nginx-module-$ver.tar.gz || exit 1
    tar -xzf echo-nginx-module-$ver.tar.gz || exit 1
    mv openresty-echo-nginx-module-* echo-nginx-module-$ver || exit 1

    cd ..
    cp $root/util/configure ./ || exit 1
    cp $root/README.markdown ./ || exit 1
    cp $root/util/install bundle/ || exit 1
}

```

### 编译

```shell
# 进入openresty目录
cd openresty-$ver

# configure: 生成调试符号
export CFLAGS="-O0 -g" && ./configure --prefix=./tmp --with-debug

# make并install到openresty-$ver/tmp下
make && make install

```

### 调试

```json

{
    "name": "nginx",
    "type": "cppdbg",
    "request": "launch",
    "preLaunchTask": "make-src",
    "postDebugTask": "stop-nginx-2",
    "program": "${workspaceFolder}/openresty-1.21.4.1/tmp/nginx/sbin/nginx",
    "args": [
        "-p", "${workspaceFolder}/openresty-1.21.4.1/tmp/nginx",
        "-g", "daemon off;"
    ],
    "stopAtEntry": false,
    "cwd": "${workspaceFolder}/openresty-1.21.4.1",
    "environment": [
        {
            "name": "LD_LIBRARY_PATH",
            "value": "${workspaceFolder}/openresty-1.21.4.1/tmp/luajit/lib"
        }
    ],
    "externalConsole": false,
    "MIMode": "gdb",
    "setupCommands": [
        {
            "description": "Enable pretty-printing for gdb",
            "text": "-enable-pretty-printing",
            "ignoreFailures": true
        },
        {
            "description": "After fork both processes will be held under the control of GDB",
            "text": "set detach-on-fork"
        }
    ]
}

```

## nginx初始化流程

```c

int main(int argc, char *const *argv)
{
    // 解析命令行参数
    ngx_get_options(argc, argv);

    // 打开logs/error.log
    log = ngx_log_init(ngx_prefix, ngx_error_log);

    // 每次reload产生新的cycle
    ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
    init_cycle.log = log;
    ngx_cycle = &init_cycle;

    // configure过程中设置的模块列表
    ngx_preinit_modules()
    {
        for (i = 0; ngx_modules[i]; i++) {
            ngx_modules[i]->index = i;
            ngx_modules[i]->name = ngx_module_names[i];
        }
    }

    cycle = ngx_init_cycle(&init_cycle /* old_cycle */);
    {
        cycle = ngx_pcalloc(pool, sizeof(ngx_cycle_t));
        cycle->old_cycle = old_cycle;

        // 初始化核心模块
        for (i = 0; cycle->modules[i]; i++) {
            if (cycle->modules[i]->type != NGX_CORE_MODULE) {
                continue;
            }

            module = cycle->modules[i]->ctx;

            // 创建context
            if (module->create_conf) {
                rv = module->create_conf(cycle);
                cycle->conf_ctx[cycle->modules[i]->index] = rv;
            }
        }

        ngx_memzero(&conf, sizeof(ngx_conf_t));
        conf.ctx = cycle->conf_ctx;
        conf.cycle = cycle;
        conf.module_type = NGX_CORE_MODULE;
        conf.cmd_type = NGX_MAIN_CONF;

        // 解析命令行参数中`-g`指定的全局参数
        ngx_conf_param(&conf);
        {
            // 设置buf指向-g指定的参数
            b.start = param->data;
            b.pos = param->data;
            b.last = param->data + param->len;
            b.end = b.last;

            conf_file.file.fd = NGX_INVALID_FILE;
            conf_file.file.name.data = NULL;
            conf_file.line = 0;

            cf->conf_file = &conf_file;
            cf->conf_file->buffer = &b;
            ngx_conf_parse(cf, NULL);
        }

        // 解析nginx.conf
        ngx_conf_parse(&conf /*cf*/, &cycle->conf_file /*filename*/);
        {
            // 配置解析
            for ( ;; ) {
                // 解析一个指令
                rc = ngx_conf_read_token(cf);
                ngx_conf_handler(cf, rc);
                {
                    for (i = 0; cf->cycle->modules[i]; i++) {
                        cmd = cf->cycle->modules[i]->commands;
                        for ( /* void */ ; cmd->name.len; cmd++) {
                            // 匹配name
                            if (ngx_strcmp(name->data, cmd->name.data) != 0) {
                                continue;
                            }

                            // 匹配module_type
                            if (cf->cycle->modules[i]->type != NGX_CONF_MODULE
                                && cf->cycle->modules[i]->type != cf->module_type)
                            {
                                continue;
                            }

                            // 匹配cmd_type
                            if (!(cmd->type & cf->cmd_type)) {
                                continue;
                            }

                            if (cmd->type & NGX_DIRECT_CONF) {
                                conf = ((void **) cf->ctx)[cf->cycle->modules[i]->index];
                            } else if (cmd->type & NGX_MAIN_CONF) {
                                conf = &(((void **) cf->ctx)[cf->cycle->modules[i]->index]);
                            } else if (cf->ctx) {
                                confp = *(void **) ((char *) cf->ctx + cmd->conf);
                                if (confp) {
                                    // 非核心模块的配置
                                    conf = confp[cf->cycle->modules[i]->ctx_index];
                                }
                            }

                            // 调用每个cmd的handler
                            rv = cmd->set(cf, cmd, conf);
                        }
                    }
                }
            }
        }

        for (i = 0; cycle->modules[i]; i++) {
            if (cycle->modules[i]->type != NGX_CORE_MODULE) {
                continue;
            }

            module = cycle->modules[i]->ctx;

            // 设置context默认值
            if (module->init_conf) {
                module->init_conf(cycle, cycle->conf_ctx[cycle->modules[i]->index]);
            }
        }

        // 打开各个模块注册的文件: logs/access.log、logs/error.log
        part = &cycle->open_files.part;
        file = part->elts;
        for (i = 0; /* void */ ; i++) {
            file[i].fd = ngx_open_file(file[i].name.data, ...);
        }

        // 设置listen指令指定的socket
        ngx_open_listening_sockets(cycle);
        {
            ls = cycle->listening.elts;
            for (i = 0; i < cycle->listening.nelts; i++) {
                s = ngx_socket(ls[i].sockaddr->sa_family, ls[i].type, 0);
                bind(s, ls[i].sockaddr, ls[i].socklen);
                listen(s, ls[i].backlog);
                ls[i].listen = 1;
                ls[i].fd = s;
            }
        }

        ngx_init_modules(cycle);
        {
            for (i = 0; cycle->modules[i]; i++) {
                if (cycle->modules[i]->init_module) {
                    cycle->modules[i]->init_module(cycle);
                }
            }
        }
    }

    // 设置`nginx -s xxx`的handler
    ngx_init_signals(cycle->log);

    if (ngx_process == NGX_PROCESS_SINGLE) {
        // `master_process off`单进程模式
        ngx_single_process_cycle(cycle);
        {
            for (i = 0; cycle->modules[i]; i++) {
                if (cycle->modules[i]->init_process) {
                    cycle->modules[i]->init_process(cycle);
                }
            }

            for ( ;; ) {
                // 事件循环
                ngx_process_events_and_timers(cycle);
                {
                    // ngx_epoll_process_events
                    ngx_process_events(cycle, timer, flags);
                    {
                        events = epoll_wait(ep, event_list, (int) nevents, timer);
                        for (i = 0; i < events; i++) {
                            c = event_list[i].data.ptr;

                            rev = c->read;
                            if ((revents & EPOLLIN) && rev->active) {
                                if (flags & NGX_POST_EVENTS) {
                                    queue = rev->accept ? &ngx_posted_accept_events
                                                        : &ngx_posted_events;
                                    ngx_post_event(rev, queue);
                                } else {
                                    rev->handler(rev);
                                }
                            }

                            wev = c->write;
                            if ((revents & EPOLLOUT) && wev->active) {
                                if (flags & NGX_POST_EVENTS) {
                                    ngx_post_event(wev, &ngx_posted_events);
                                } else {
                                    wev->handler(wev);
                                }
                            }
                        }
                    }

                    // 处理定时事件
                    ngx_event_expire_timers();
                }
            }
        }
    } else {
        // 默认master/worker多进程模式
        ngx_master_process_cycle(cycle);
        {
            // 事件循环
            ngx_start_worker_processes(cycle, ccf->worker_processes, NGX_PROCESS_RESPAWN);
            {
                for (i = 0; i < n; i++) {
                    ngx_spawn_process(cycle, ngx_worker_process_cycle, (void *) (intptr_t) i, ...);
                    {
                        for ( ;; ) {
                            ngx_process_events_and_timers(cycle);
                        }
                    }
                }
            }

            ngx_start_cache_manager_processes(cycle, 0);
            {
                ngx_spawn_process(cycle, ngx_cache_manager_process_cycle,
                                  &ngx_cache_manager_ctx, "cache manager process", ...);

                ngx_spawn_process(cycle, ngx_cache_manager_process_cycle,
                                  &ngx_cache_loader_ctx, "cache loader process", ...);
            }

            ngx_start_privileged_agent_processes(cycle, 0);

            // 处理各种signal
            for ( ;; ) {

            }
        }
    }
}

```

## 关键模块

`nginx`的模块化设计非常优秀，值得借鉴。

### 模块列表

```c

// configure过程中设置的模块列表
ngx_module_t *ngx_modules[] = {
    // 核心模块
    &ngx_core_module,

    &ngx_errlog_module,
    &ngx_conf_module,

    &ngx_openssl_module,
    &ngx_regex_module,

    // event模块
    &ngx_events_module,
    &ngx_event_core_module,
    &ngx_epoll_module,

    // http: 7层代理
    &ngx_http_module,
    &ngx_http_core_module,

    &ngx_http_log_module,
    &ngx_http_upstream_module,
    &ngx_http_static_module,
    &ngx_http_autoindex_module,
    &ngx_http_index_module,
    &ngx_http_mirror_module,
    &ngx_http_try_files_module,
    &ngx_http_auth_basic_module,
    &ngx_http_access_module,
    &ngx_http_limit_conn_module,
    &ngx_http_limit_req_module,
    &ngx_http_geo_module,
    &ngx_http_map_module,
    &ngx_http_split_clients_module,
    &ngx_http_referer_module,
    &ngx_http_rewrite_module,
    &ngx_http_ssl_module,
    &ngx_http_proxy_module,
    &ngx_http_fastcgi_module,
    &ngx_http_uwsgi_module,
    &ngx_http_scgi_module,
    &ngx_http_memcached_module,
    &ngx_http_empty_gif_module,
    &ngx_http_browser_module,
    &ngx_http_upstream_hash_module,
    &ngx_http_upstream_ip_hash_module,
    &ngx_http_upstream_least_conn_module,
    &ngx_http_upstream_random_module,
    &ngx_http_upstream_keepalive_module,
    &ngx_http_upstream_zone_module,
    &ndk_http_module,
    &ngx_coolkit_module,
    &ngx_http_set_misc_module,
    &ngx_http_form_input_module,
    &ngx_http_encrypted_session_module,
    &ngx_http_lua_upstream_module,
    &ngx_http_array_var_module,
    &ngx_http_memc_module,
    &ngx_http_redis2_module,
    &ngx_http_redis_module,
    &ngx_http_write_filter_module,
    &ngx_http_header_filter_module,
    &ngx_http_chunked_filter_module,
    &ngx_http_range_header_filter_module,
    &ngx_http_gzip_filter_module,
    &ngx_http_postpone_filter_module,
    &ngx_http_ssi_filter_module,
    &ngx_http_charset_filter_module,
    &ngx_http_userid_filter_module,
    &ngx_http_headers_filter_module,
    &ngx_http_echo_module,
    &ngx_http_xss_filter_module,
    &ngx_http_srcache_filter_module,
    &ngx_http_lua_module,
    &ngx_http_headers_more_filter_module,
    &ngx_http_rds_json_filter_module,
    &ngx_http_rds_csv_filter_module,
    &ngx_http_copy_filter_module,
    &ngx_http_range_body_filter_module,
    &ngx_http_not_modified_filter_module,

    // stream: 4层代理
    &ngx_stream_module,
    &ngx_stream_core_module,

    &ngx_stream_log_module,
    &ngx_stream_proxy_module,
    &ngx_stream_upstream_module,
    &ngx_stream_write_filter_module,
    &ngx_stream_ssl_module,
    &ngx_stream_limit_conn_module,
    &ngx_stream_access_module,
    &ngx_stream_geo_module,
    &ngx_stream_map_module,
    &ngx_stream_split_clients_module,
    &ngx_stream_return_module,
    &ngx_stream_set_module,
    &ngx_stream_upstream_hash_module,
    &ngx_stream_upstream_least_conn_module,
    &ngx_stream_upstream_random_module,
    &ngx_stream_upstream_zone_module,
    &ngx_stream_ssl_preread_module,
    &ngx_stream_lua_module,
    NULL
};

```

### 配置文件

`nginx.conf`文件组装了各个模块下的指令，`block`类型的指令允许嵌套其他指令

```shell

# 最外层只能出现NGX_CORE_MODULE下NGX_MAIN_CONF类型的指令

# ngx_core_module
#user  nobody;
worker_processes  1;

# ngx_errlog_module
error_log  logs/error.log  debug;

# ngx_events_module
events {
    # ngx_event_core_module
    worker_connections  1024;
}

# ngx_http_module
http {
    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    server {
        listen       8088;
        server_name  localhost;

        #access_log  logs/host.access.log  main;

        location / {
            root   html;
            index  index.html index.htm;
        }

        location /hello {
            default_type text/plain;
            content_by_lua_block {
                ngx.say("Hello World")
            }
        }

        #error_page  404              /404.html;

        # redirect server error pages to the static page /50x.html
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
    }

}

```

### ngx_core_module

```c

// 指令类型决定指令的位置
static ngx_command_t  ngx_core_commands[] = {

    { ngx_string("daemon"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_core_conf_t, daemon),
      NULL },

    { ngx_string("master_process"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_core_conf_t, master),
      NULL },

    { ngx_string("pid"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_core_conf_t, pid),
      NULL },

    { ngx_string("lock_file"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_core_conf_t, lock_file),
      NULL },

    { ngx_string("worker_processes"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_set_worker_processes,
      0,
      0,
      NULL },

    { ngx_string("user"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE12,
      ngx_set_user,
      0,
      0,
      NULL },

    { ngx_string("worker_priority"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_set_priority,
      0,
      0,
      NULL },

    { ngx_string("worker_cpu_affinity"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_1MORE,
      ngx_set_cpu_affinity,
      0,
      0,
      NULL },

    { ngx_string("worker_rlimit_nofile"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_core_conf_t, rlimit_nofile),
      NULL },

    { ngx_string("worker_rlimit_core"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_off_slot,
      0,
      offsetof(ngx_core_conf_t, rlimit_core),
      NULL },

    { ngx_string("worker_shutdown_timeout"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      0,
      offsetof(ngx_core_conf_t, shutdown_timeout),
      NULL },

    { ngx_string("working_directory"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_core_conf_t, working_directory),
      NULL },

    { ngx_string("env"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_set_env,
      0,
      0,
      NULL },

    { ngx_string("load_module"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_load_module,
      0,
      0,
      NULL },

      ngx_null_command
};

static ngx_core_module_t  ngx_core_module_ctx = {
    ngx_string("core"),
    // 创建模块配置
    ngx_core_module_create_conf,
    // 设置默认值
    ngx_core_module_init_conf
};

ngx_module_t  ngx_core_module = {
    NGX_MODULE_V1,
    &ngx_core_module_ctx,                  /* module context */
    ngx_core_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

```

### ngx_events_module

```c

static ngx_command_t  ngx_events_commands[] = {

    { ngx_string("events"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_events_block,
      0,
      0,
      NULL },

      ngx_null_command
};

static ngx_core_module_t  ngx_events_module_ctx = {
    ngx_string("events"),
    NULL,
    ngx_event_init_conf
};

ngx_module_t  ngx_events_module = {
    NGX_MODULE_V1,
    &ngx_events_module_ctx,                /* module context */
    ngx_events_commands,                   /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


// event块指令
static char *
ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    // 设置ctx_index
    ngx_event_max_module = ngx_count_modules(cf->cycle, NGX_EVENT_MODULE);

    // 初始化所有的event模块
    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != NGX_EVENT_MODULE) {
            continue;
        }

        m = cf->cycle->modules[i]->ctx;

        if (m->create_conf) {
            (*ctx)[cf->cycle->modules[i]->ctx_index] = m->create_conf(cf->cycle);
        }
    }

    // 备份ngx_conf_t
    pcf = *cf;
    cf->ctx = ctx;
    // 设置module_type和cmd_type
    cf->module_type = NGX_EVENT_MODULE;
    cf->cmd_type = NGX_EVENT_CONF;

    // 解析event模块的配置
    rv = ngx_conf_parse(cf, NULL);

    // 还原ngx_conf_t
    *cf = pcf;
}

```

### ngx_event_core_module

```c

static ngx_event_module_t  ngx_epoll_module_ctx = {
    &epoll_name,
    ngx_epoll_create_conf,               /* create configuration */
    ngx_epoll_init_conf,                 /* init configuration */

    {
        ngx_epoll_add_event,             /* add an event */
        ngx_epoll_del_event,             /* delete an event */
        ngx_epoll_add_event,             /* enable an event */
        ngx_epoll_del_event,             /* disable an event */
        ngx_epoll_add_connection,        /* add an connection */
        ngx_epoll_del_connection,        /* delete an connection */
        ngx_epoll_notify,                /* trigger a notify */
        ngx_epoll_process_events,        /* process the events */
        ngx_epoll_init,                  /* init the events */
        ngx_epoll_done,                  /* done the events */
    }
};

static ngx_command_t  ngx_event_core_commands[] = {

    { ngx_string("worker_connections"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_connections,
      0,
      0,
      NULL },

      ngx_null_command
};

ngx_module_t  ngx_event_core_module = {
    NGX_MODULE_V1,
    &ngx_event_core_module_ctx,            /* module context */
    ngx_event_core_commands,               /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init master */
    ngx_event_module_init,                 /* init module */
    ngx_event_process_init,                /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static char * ngx_event_core_init_conf(ngx_cycle_t *cycle, void *conf)
{
    // 测试是否支持epoll
    fd = epoll_create(100);
    if (fd != -1) {
        (void) close(fd);
        module = &ngx_epoll_module;
    }

    // 记录epoll模块的位置
    ngx_conf_init_uint_value(ecf->use, module->ctx_index);
}

static ngx_int_t ngx_event_process_init(ngx_cycle_t *cycle)
{
    ngx_event_timer_init(cycle->log);

    for (m = 0; cycle->modules[m]; m++) {
        if (cycle->modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        // epoll所在模块
        if (cycle->modules[m]->ctx_index != ecf->use) {
            continue;
        }

        module = cycle->modules[m]->ctx;

        // ngx_epoll_init
        module->actions.init(cycle, ngx_timer_resolution);
        {
            ep = epoll_create(cycle->connection_n / 2);
            ngx_event_actions = ngx_epoll_module_ctx.actions;
        }

        break;
    }

    // worker_connections指定的连接数
    cycle->connections = ngx_alloc(sizeof(ngx_connection_t) * cycle->connection_n, cycle->log);
    cycle->read_events = ngx_alloc(sizeof(ngx_event_t) * cycle->connection_n, cycle->log);
    cycle->write_events = ngx_alloc(sizeof(ngx_event_t) * cycle->connection_n, cycle->log);

    c = cycle->connections;
    i = cycle->connection_n;

    do {
        i--;

        c[i].data = next;
        c[i].read = &cycle->read_events[i];
        c[i].write = &cycle->write_events[i];
        c[i].fd = (ngx_socket_t) -1;

        next = &c[i];
    } while (i);

    cycle->free_connections = next;
    cycle->free_connection_n = cycle->connection_n;

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        // 获取空闲连接
        c = ngx_get_connection(ls[i].fd, cycle->log);
        rev = c->read;
        // 设置handler
        rev->handler = (c->type == SOCK_STREAM) ? ngx_event_accept
                                                : ngx_event_recvmsg;
        // 注册listen指令的read事件
        ngx_add_event(rev, NGX_READ_EVENT, 0);
    }
}

// 处理连接事件
void ngx_event_accept(ngx_event_t *ev)
{
    lc = ev->data;
    ls = lc->listening;

    s = accept4(lc->fd, &sa.sockaddr, &socklen, SOCK_NONBLOCK | SOCK_CLOEXEC);

    c = ngx_get_connection(s, ev->log);
    c->type = SOCK_STREAM;
    c->recv = ngx_recv;
    c->send = ngx_send;
    c->listening = ls;
    c->local_sockaddr = ls->sockaddr;
    c->local_socklen = ls->socklen;

    rev = c->read;
    wev = c->write;

    // 注册到event循环
    ngx_add_conn(c);

    // 由listen指令所在模块处理
    ls->handler(c);
}

```

### ngx_http_module

```c

static ngx_command_t  ngx_http_commands[] = {

    { ngx_string("http"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_http_block,
      0,
      0,
      NULL },

      ngx_null_command
};

static ngx_core_module_t  ngx_http_module_ctx = {
    ngx_string("http"),
    NULL,
    NULL
};

ngx_module_t  ngx_http_module = {
    NGX_MODULE_V1,
    &ngx_http_module_ctx,                  /* module context */
    ngx_http_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static char * ngx_http_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    // 设置ctx_index: 给每个http模块找个空闲位置
    ngx_http_max_module = ngx_count_modules(cf->cycle, NGX_HTTP_MODULE);

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
        }

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
        }

        if (module->create_loc_conf) {
            ctx->loc_conf[mi] = module->create_loc_conf(cf);
        }
    }

    pcf = *cf;
    cf->ctx = ctx;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->preconfiguration) {
            module->preconfiguration(cf);
        }
    }

    cf->module_type = NGX_HTTP_MODULE;
    cf->cmd_type = NGX_HTTP_MAIN_CONF;

    // 解析http模块的配置
    rv = ngx_conf_parse(cf, NULL);

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        // 每个http模块都可以修改http配置
        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
        }

        rv = ngx_http_merge_servers(cf, cmcf, module, mi);
    }

    /* create location trees */
    for (s = 0; s < cmcf->servers.nelts; s++) {
        clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];
        ngx_http_init_locations(cf, cscfp[s], clcf);
        ngx_http_init_static_location_trees(cf, clcf);
    }

    ngx_http_init_phases(cf, cmcf);
    ngx_http_init_headers_in_hash(cf, cmcf);

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->postconfiguration) {
            module->postconfiguration(cf);
        }
    }

    ngx_http_variables_init_vars(cf);

    // http请求处理阶段
    typedef enum {
        NGX_HTTP_POST_READ_PHASE = 0,

        NGX_HTTP_SERVER_REWRITE_PHASE,

        NGX_HTTP_FIND_CONFIG_PHASE,
        NGX_HTTP_REWRITE_PHASE,
        NGX_HTTP_POST_REWRITE_PHASE,

        NGX_HTTP_PREACCESS_PHASE,

        NGX_HTTP_ACCESS_PHASE,
        NGX_HTTP_POST_ACCESS_PHASE,

        NGX_HTTP_PRECONTENT_PHASE,

        NGX_HTTP_CONTENT_PHASE,

        NGX_HTTP_LOG_PHASE
    } ngx_http_phases;

    // 每个http模块可以注册handler到各个phase
    ngx_http_init_phase_handlers(cf, cmcf);
    {
        for (i = 0; i < NGX_HTTP_LOG_PHASE; i++) {
            h = cmcf->phases[i].handlers.elts;

            switch (i) {

            case NGX_HTTP_SERVER_REWRITE_PHASE:

                checker = ngx_http_core_rewrite_phase;

                break;

            case NGX_HTTP_FIND_CONFIG_PHASE:
                find_config_index = n;

                ph->checker = ngx_http_core_find_config_phase;
                n++;
                ph++;

                continue;

            case NGX_HTTP_REWRITE_PHASE:
                
                checker = ngx_http_core_rewrite_phase;

                break;

            case NGX_HTTP_POST_REWRITE_PHASE:
                if (use_rewrite) {
                    ph->checker = ngx_http_core_post_rewrite_phase;
                    ph->next = find_config_index;
                    n++;
                    ph++;
                }

                continue;

            case NGX_HTTP_ACCESS_PHASE:
                checker = ngx_http_core_access_phase;
                n++;
                break;

            case NGX_HTTP_POST_ACCESS_PHASE:
                if (use_access) {
                    ph->checker = ngx_http_core_post_access_phase;
                    ph->next = n;
                    ph++;
                }

                continue;

            case NGX_HTTP_CONTENT_PHASE:
                checker = ngx_http_core_content_phase;
                break;

            default:
                checker = ngx_http_core_generic_phase;
            }

            n += cmcf->phases[i].handlers.nelts;

            for (j = cmcf->phases[i].handlers.nelts - 1; j >= 0; j--) {
                ph->checker = checker;
                ph->handler = h[j];
                ph->next = n;
                ph++;
            }
        }
    }

    ngx_http_optimize_servers(cf, cmcf, cmcf->ports);
    {
        port = ports->elts;
        for (p = 0; p < ports->nelts; p++) {
            ngx_http_init_listening(cf, &port[p]);
            {
                ngx_http_add_listening(cf, &addr[i]);
                {
                    ls = ngx_create_listening(cf, addr->opt.sockaddr, addr->opt.socklen);
                    // 设置accept后的handler
                    ls->handler = ngx_http_init_connection;
                    {
                        rev = c->read;
                        rev->handler = ngx_http_wait_request_handler;
                        {
                            // 读取请求数据
                            n = c->recv(c, b->last, size);

                            rev->handler = ngx_http_process_request_line;
                            ngx_http_process_request_line(rev);
                            {
                                ngx_http_parse_request_line(r, r->header_in);
                                {
                                    rev->handler = ngx_http_process_request_headers;
                                    ngx_http_process_request_headers(rev);
                                    {
                                        ngx_http_read_request_header(r);
                                        ngx_http_parse_header_line(r, r->header_in, cscf->underscores_in_headers);

                                        ngx_http_process_request(r);
                                        {
                                            c->read->handler = ngx_http_request_handler;
                                            c->write->handler = ngx_http_request_handler;
                                            r->read_event_handler = ngx_http_block_reading;

                                            ngx_http_handler(r);
                                            {
                                                r->write_event_handler = ngx_http_core_run_phases;
                                                // 责任链模式
                                                ngx_http_core_run_phases(r);
                                                {
                                                    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
                                                    ph = cmcf->phase_engine.handlers;

                                                    while (ph[r->phase_handler].checker) {
                                                        rc = ph[r->phase_handler].checker(r, &ph[r->phase_handler]);
                                                        if (rc == NGX_OK) {
                                                            return;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        c->write->handler = ngx_http_empty_handler;

                        // 注册read事件
                        ngx_handle_read_event(rev, 0);
                    }
                }
            }
        }
    }
}

```

### ngx_http_core_module

```c

// NGX_HTTP_MAIN_CONF类型的指令可以直接出现在http块下
// NGX_HTTP_SRV_CONF类型的指令可以直接出现在server块下
// NGX_HTTP_LOC_CONF类型的指令可以直接出现在location块下
static ngx_command_t  ngx_http_core_commands[] = {

    // server指令位于http块下
    { ngx_string("server"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_http_core_server,
      0,
      0,
      NULL },

    { ngx_string("connection_pool_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, connection_pool_size),
      &ngx_http_core_pool_size_p },

    { ngx_string("request_pool_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, request_pool_size),
      &ngx_http_core_pool_size_p },

    { ngx_string("client_header_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_core_srv_conf_t, client_header_timeout),
      NULL },
    
    // location指令位于server块下
    { ngx_string("location"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE12,
      ngx_http_core_location,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    // listen指令位于server块下
    { ngx_string("listen"),
      NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_core_listen,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("server_name"),
      NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_core_server_name,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_http_core_types,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("default_type"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, default_type),
      NULL },

    // root指令可以位于http/server/location块下
    { ngx_string("root"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_core_root,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("client_max_body_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_off_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, client_max_body_size),
      NULL },

    { ngx_string("client_body_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, client_body_buffer_size),
      NULL },

    { ngx_string("client_body_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, client_body_timeout),
      NULL },

    { ngx_string("limit_rate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, limit_rate),
      NULL },

    { ngx_string("keepalive_time"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_core_loc_conf_t, keepalive_time),
      NULL },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_core_module_ctx = {
    ngx_http_core_preconfiguration,        /* preconfiguration */
    ngx_http_core_postconfiguration,       /* postconfiguration */

    ngx_http_core_create_main_conf,        /* create main configuration */
    ngx_http_core_init_main_conf,          /* init main configuration */

    ngx_http_core_create_srv_conf,         /* create server configuration */
    ngx_http_core_merge_srv_conf,          /* merge server configuration */

    ngx_http_core_create_loc_conf,         /* create location configuration */
    ngx_http_core_merge_loc_conf           /* merge location configuration */
};

ngx_module_t  ngx_http_core_module = {
    NGX_MODULE_V1,
    &ngx_http_core_module_ctx,             /* module context */
    ngx_http_core_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

// listen指令
static char * ngx_http_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    for (n = 0; n < u.naddrs; n++) {
        lsopt.sockaddr = u.addrs[n].sockaddr;
        lsopt.socklen = u.addrs[n].socklen;
        lsopt.addr_text = u.addrs[n].name;
        lsopt.wildcard = ngx_inet_wildcard(lsopt.sockaddr);

        // 注册listening
        ngx_http_add_listen(cf, cscf, &lsopt);
    }
}

```

### ngx_stream_module

```c

static ngx_command_t  ngx_stream_commands[] = {

    { ngx_string("stream"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_stream_block,
      0,
      0,
      NULL },

      ngx_null_command
};

static ngx_core_module_t  ngx_stream_module_ctx = {
    ngx_string("stream"),
    NULL,
    NULL
};

ngx_module_t  ngx_stream_module = {
    NGX_MODULE_V1,
    &ngx_stream_module_ctx,                /* module context */
    ngx_stream_commands,                   /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *
ngx_stream_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_max_module = ngx_count_modules(cf->cycle, NGX_STREAM_MODULE);

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
        }

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
        }
    }

    pcf = *cf;
    cf->ctx = ctx;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->preconfiguration) {
            module->preconfiguration(cf);
        }
    }

    cf->module_type = NGX_STREAM_MODULE;
    cf->cmd_type = NGX_STREAM_MAIN_CONF;

    // 解析stream模块
    rv = ngx_conf_parse(cf, NULL);

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        cf->ctx = ctx;

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
        }

        for (s = 0; s < cmcf->servers.nelts; s++) {
            cf->ctx = cscfp[s]->ctx;

            if (module->merge_srv_conf) {
                rv = module->merge_srv_conf(cf, ctx->srv_conf[mi], cscfp[s]->ctx->srv_conf[mi]);
            }
        }
    }

    ngx_stream_init_phases(cf, cmcf);

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->postconfiguration) {
            module->postconfiguration(cf);
        }
    }

    ngx_stream_variables_init_vars(cf);

    // stream请求处理阶段
    typedef enum {
        NGX_STREAM_POST_ACCEPT_PHASE = 0,
        NGX_STREAM_PREACCESS_PHASE,
        NGX_STREAM_ACCESS_PHASE,
        NGX_STREAM_SSL_PHASE,
        NGX_STREAM_PREREAD_PHASE,
        NGX_STREAM_CONTENT_PHASE,
        NGX_STREAM_LOG_PHASE
    } ngx_stream_phases;

    // 责任链模式: 允许stream模块注册handler到各个phase
    ngx_stream_init_phase_handlers(cf, cmcf);

    listen = cmcf->listen.elts;
    for (i = 0; i < cmcf->listen.nelts; i++) {
        ngx_stream_add_ports(cf, &ports, &listen[i]);
    }

    ngx_stream_optimize_servers(cf, &ports);
    {
        ls = ngx_create_listening(cf, addr[i].opt.sockaddr, addr[i].opt.socklen);
        ls->handler = ngx_stream_init_connection;
    }
}

```
