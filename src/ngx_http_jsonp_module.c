#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* I tried to resist the urge to completely rewrite this*/


// JSONP mimetype
static ngx_str_t ngx_http_jsonp_mimetype = ngx_string("application/javascript");
// Variable name
static ngx_str_t ngx_http_jsonp_callback_variable_name = ngx_string("jsonp_callback");
static ngx_int_t ngx_http_jsonp_callback_variable_index;
// Default applicable mimetypes
static ngx_str_t ngx_http_jsonp_default_mimetypes[] = {
    ngx_string("application/json"),
    ngx_null_string
};


// Configuration structure
// will hold runtime configuration
// options
typedef struct {
    ngx_flag_t      enable;
    ngx_hash_t      mimetypes;
    ngx_array_t   * mimetypes_keys;
} ngx_http_jsonp_conf_t;

// Runtime context structure
// will store data needed by the filter
// over a request
typedef struct {
    unsigned prefix:1;
    ngx_str_t callback;
} ngx_http_jsonp_ctx_t;

static void * ngx_http_jsonp_create_conf(ngx_conf_t *cf);
static char * ngx_http_jsonp_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_jsonp_body_filter( ngx_http_request_t *r, ngx_chain_t *in );
static ngx_int_t ngx_http_jsonp_header_filter( ngx_http_request_t *r );
static ngx_int_t ngx_http_jsonp_filter_init( ngx_conf_t * cf );



// Configuration directives for this module
static ngx_command_t  ngx_http_jsonp_filter_commands[] = {
    { ngx_string("jsonp"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jsonp_conf_t, enable),
      NULL },

    { ngx_string("jsonp_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF
                        |NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jsonp_conf_t, mimetypes_keys),
      &ngx_http_jsonp_default_mimetypes[0]  }
};


static ngx_http_module_t  ngx_http_jsonp_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_jsonp_filter_init,       /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_jsonp_create_conf,       /* create location configuration */
    ngx_http_jsonp_merge_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_jsonp_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_jsonp_filter_module_ctx,     /* module context */
    ngx_http_jsonp_filter_commands,        /* module directives */
    NGX_HTTP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    NULL,                                       /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

// Initialize a configuration structure
static void * ngx_http_jsonp_create_conf(ngx_conf_t *cf)
{
    ngx_http_jsonp_conf_t * json_conf;
    json_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jsonp_conf_t));

    json_conf->enable = NGX_CONF_UNSET;

    return json_conf;
}

// Merge a child configuration with a parent one
static char * ngx_http_jsonp_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_jsonp_conf_t *prev = parent;
    ngx_http_jsonp_conf_t *conf = child;

    // This is trivial, as we have only enable to merge
    // note the 0 default value
    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    // Merge the applicable mimetypes
    if (ngx_http_merge_types(cf, &conf->mimetypes_keys, &conf->mimetypes,
                             &prev->mimetypes_keys, &prev->mimetypes,
                             ngx_http_jsonp_default_mimetypes) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


// Response header filter
static ngx_int_t ngx_http_jsonp_header_filter( ngx_http_request_t *r )
{
    ngx_http_jsonp_conf_t * cf;
    ngx_http_jsonp_ctx_t * ctx;
    ngx_http_variable_value_t *callback;

    // Getting the current configuration object
    cf = ngx_http_get_module_loc_conf(r, ngx_http_jsonp_filter_module);

    if (r != r->main) {
        return ngx_http_next_header_filter(r);
    }

    if (cf->enable && r->headers_out.status == NGX_HTTP_OK
        && !r->header_only ) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http jsonp filter");
        return ngx_http_next_header_filter(r);
    }

    // Do we have a content type matching the ones provided
    // in the configuration?
    if ( ngx_http_test_content_type(r, &cf->mimetypes) == NULL ) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http jsonp filter: enabled but not configured for this mimetype");
        return ngx_http_next_header_filter(r);
    }

    callback = ngx_http_get_indexed_variable(r, ngx_http_jsonp_callback_variable_index);

    if (callback == NULL) {
        /*this should be fatal...*/
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "http jsonp filter: ngx_http_get_indexed_variable returned NULL");
        return ngx_http_next_header_filter(r);
        /*return NGX_HTTP_INTERNAL_SERVER_ERROR;*/
    }

    if(callback->not_found || callback->len == 0) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "http jsonp filter: the \"%V\" variable is not set",
                      &ngx_http_jsonp_callback_variable_name);
        return ngx_http_next_header_filter(r);
    }

    // Allocating a new request context for the body filter
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_jsonp_ctx_t));

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    // Store the variable in the context
    ctx->callback.len = callback->len;
    ctx->callback.data = callback->data;
    ngx_http_set_ctx(r, ctx, ngx_http_jsonp_filter_module);

    // JSONP is has a text/javascript mimetype, let's change the Content-Type
    // header for the response
    /* TODO: make configurable */
    r->headers_out.content_type = ngx_http_jsonp_mimetype;
    r->headers_out.content_type_len = ngx_http_jsonp_mimetype.len;
    r->headers_out.content_type_lowcase = NULL;

    ngx_http_clear_content_length(r);
    ngx_http_clear_accept_ranges(r);

    /* XXX: I think the content length stuff may be what causes short reads??? It usually works, but what if something down stream does not reset it if we use SSI?*/
    /* if (r->headers_out.content_length_n != -1) { */
    /*     size_t len = r->headers_out.content_length_n + callback->len + 1 + sizeof(");") - 1; */
    /*     ngx_http_clear_content_length(r); */
    /*     r->headers_out.content_length_n = len; */
    /* } */

    return ngx_http_next_header_filter(r);
}


// Response body filter
static ngx_int_t ngx_http_jsonp_body_filter( ngx_http_request_t *r, ngx_chain_t *in )
{
    ngx_http_jsonp_ctx_t *ctx;
    ngx_uint_t last;
    ngx_chain_t *cl, *orig_in;
    ngx_chain_t **ll = NULL;
    size_t len;
    ngx_buf_t *b;

    if (in == NULL || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    // Get the context set by the header filter
    ctx = ngx_http_get_module_ctx(r, ngx_http_jsonp_filter_module);

    if (ctx == NULL) {
        // The filter is not active
        // (for whatever reason)
        return ngx_http_next_body_filter(r, in);
    }

    orig_in = in;
    // This is the first buffer chain we see for this request?
    if (!ctx->prefix) {
        ctx->prefix = 1;
        len = ctx->callback.len + sizeof("(") - 1;

        b = ngx_create_temp_buf(r->pool, len);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->last = ngx_copy(b->last, ctx->callback.data, ctx->callback.len);

        *b->last++ = '(';

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = b;
        cl->next = in;
        in = cl;
    }

    last = 0;

    for (cl = orig_in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            cl->buf->last_buf = 0;
            cl->buf->sync = 1;
            ll = &cl->next;
            last = 1;
        }
    }

    if (last) {
        len = sizeof(");") - 1;

        b = ngx_create_temp_buf(r->pool, len);
        if (b == NULL) {
            return NGX_ERROR;
        }

        *b->last++ = ')';
        *b->last++ = ';';

        b->last_buf = 1;

        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = b;
        cl->next = NULL;
        *ll = cl;

        ngx_http_set_ctx(r, NULL, ngx_http_jsonp_filter_module);
    }

    return ngx_http_next_body_filter(r, in);
}

static ngx_int_t
ngx_http_jsonp_filter_variable_not_found(ngx_http_request_t *r,
        ngx_http_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;
    return NGX_OK;
}

static ngx_int_t
ngx_http_jsonp_filter_add_variable(ngx_conf_t *cf, ngx_str_t *name) {
    ngx_http_variable_t *v;

    v = ngx_http_add_variable(cf, name, NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_ERROR;
    }

    v->get_handler = ngx_http_jsonp_filter_variable_not_found;

    return ngx_http_get_variable_index(cf, name);
}

// Initialization function, chain our filter on the global filter
// list
static ngx_int_t ngx_http_jsonp_filter_init( ngx_conf_t * cf )
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_jsonp_body_filter;
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_jsonp_header_filter;

    if ((ngx_http_jsonp_callback_variable_index = ngx_http_jsonp_filter_add_variable(
             cf, &ngx_http_jsonp_callback_variable_name)) == NGX_ERROR) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
