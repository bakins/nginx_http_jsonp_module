#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


// JSONP mimetype
ngx_str_t ngx_http_jsonp_mimetype = ngx_string("application/javascript");
// Variable name
ngx_str_t ngx_http_jsonp_callback_variable_name = ngx_string("jsonp_callback");
// Default applicable mimetypes
ngx_str_t ngx_http_jsonp_default_mimetypes[] = {
    ngx_string("application/json"),
    ngx_null_string
};


// Configuration structure
// will hold runtime configuration
// options
typedef struct {
    ngx_flag_t      enable;
    ngx_int_t       variable_index;

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



static char * ngx_http_jsonp_directive_jsonp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
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
      ngx_http_jsonp_directive_jsonp,
      //ngx_conf_set_flag_slot,
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



// Parse the jsonp directive
static char * ngx_http_jsonp_directive_jsonp(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    // Actually, we just get the index of the variable for the config object
    // then let the built-in flag processing function do the rest
    ngx_http_jsonp_conf_t * jsonp_cf = conf;
    jsonp_cf->variable_index = ngx_http_get_variable_index(cf, &ngx_http_jsonp_callback_variable_name);

    if (jsonp_cf->variable_index == NGX_ERROR)
    {
        return NGX_CONF_ERROR;
    }

    return ngx_conf_set_flag_slot(cf, cmd, conf);
}



// Initialize a configuration structure
static void * ngx_http_jsonp_create_conf(ngx_conf_t *cf)
{
    ngx_http_jsonp_conf_t * json_conf;
    json_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jsonp_conf_t));

    json_conf->enable = NGX_CONF_UNSET;
    json_conf->variable_index = NGX_CONF_UNSET;

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

    // Inherit the variable index from the parent
    // if not defined
    if (conf->variable_index == NGX_CONF_UNSET)
    {
        conf->variable_index = prev->variable_index;
    }


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
    ngx_http_variable_value_t * callback;

    // Getting the current configuration object
    cf = ngx_http_get_module_loc_conf(r, ngx_http_jsonp_filter_module);

    if (cf->enable && r->headers_out.status == NGX_HTTP_OK
                   && !r->header_only )
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http jsonp filter");

        // Do we have a content type matching the ones provided
        // in the configuration?
        if ( ngx_http_test_content_type(r, &cf->mimetypes) == NULL )
        {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                "http jsonp filter: enabled but not configured for this mimetype");
        }
        else
        {
            // Get the callback name from variable
            // and store it in the context
            callback = ngx_http_get_indexed_variable(r, cf->variable_index);

            if (callback == NULL || callback->not_found || callback->len == 0) {
                ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                    "http jsonp filter: the \"%V\" variable is not set",
                    &ngx_http_jsonp_callback_variable_name);
                // We will not return an error on this case
                // return NGX_ERROR
            }
            else
            {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http jsonp filter: json callback is \"%v\"", callback);

                // Allocating a new request context for the body filter
                ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_jsonp_ctx_t));
                if (ctx == NULL)
                {
                    return NGX_ERROR;
                }
                // Store the variable in the context
                ctx->callback.len = callback->len;
                ctx->callback.data = callback->data;
                ngx_http_set_ctx(r, ctx, ngx_http_jsonp_filter_module);

                // JSONP is has a text/javascript mimetype, let's change the Content-Type
                // header for the response
                r->headers_out.content_type = ngx_http_jsonp_mimetype;
                r->headers_out.content_type_len = ngx_http_jsonp_mimetype.len;
                r->headers_out.content_type_lowcase = NULL;

                // Modifying the content lenght if it is set,
                // adding the length of the json padding
                if (r->headers_out.content_length_n != -1)
                {
                    size_t len = r->headers_out.content_length_n + callback->len + 1 + sizeof(");") - 1;
                    ngx_http_clear_content_length(r);
                    r->headers_out.content_length_n = len;
                }
            }
        }
    }

    return ngx_http_next_header_filter(r);
}


// Response body filter
static ngx_int_t ngx_http_jsonp_body_filter( ngx_http_request_t *r, ngx_chain_t *in )
{
    ngx_http_jsonp_ctx_t * ctx;
    ngx_buf_t * buf, * buf_swap;
    ngx_chain_t * chain, * last;

    // Get the context set by the header filter
    ctx = ngx_http_get_module_ctx(r, ngx_http_jsonp_filter_module);

    if (ctx == NULL) {
        // The filter is not active
        // (for whatever reason)
        return ngx_http_next_body_filter(r, in);
    }

    // This is the first buffer chain we see for this request?
    if (!ctx->prefix) {
        // Insert the function name
        // Allocate a new buffer for that, and a new link
        // in the response buffer chain
        buf = ngx_create_temp_buf(r->pool, ctx->callback.len + 1);
        chain = ngx_alloc_chain_link(r->pool);

        if (buf == NULL || chain == NULL) {
            return NGX_ERROR;
        }

        // Initialize the buffer with the right content and length
        ngx_memcpy(buf->pos, ctx->callback.data, ctx->callback.len);
        buf->pos[ctx->callback.len] = '(';
        buf->last = buf->pos + ctx->callback.len + 1;

        // Let's replace insert that new buffer+link in front of the
        // buffer chain
        chain->buf = buf;
        chain->next = in;
        in = chain;

        // Prefix has been append to the response body,
        // set the flag so we won't process again if we receive another
        // chain of buffer later
        ctx->prefix = 1;
    }

    // Let's find out if we have the last content buffer in the chain
    for (chain = in, last = NULL; last == NULL && chain != NULL; chain = chain->next) {
        if (chain->buf->last_buf) {
            last = chain;
        }
    }

    if (last) {
        // this is the last chain link,
        // same as above, we insert the closing ');'
        buf = ngx_calloc_buf(r->pool);
        chain = ngx_alloc_chain_link(r->pool);

        if (buf == NULL || chain == NULL) {
            return NGX_ERROR;
        }

        buf->pos = (u_char *) ");";
        buf->last = buf->pos + sizeof(");") - 1;
        buf->memory = 1;

        // Inserting the new link at the end
        chain->buf = buf;
        chain->next = NULL;
        last->next = chain;


        // Buffer stores a flag indicating if it is the last
        // one in the response body, we need to swap that flag
        last->buf->last_buf = 0;

        // If the last buffer we had is now empty and not special, nginx will
        // err (ex: with an empty file). So we keep that buffer as the last one
        // in that case
        if ( ngx_buf_size(last->buf) == 0 && !ngx_buf_special(last->buf) )
        {
            // Back to last buffer
            last->buf->last_buf = 1;
            buf_swap = last->buf;
            last->buf = chain->buf;
            chain->buf = buf_swap;
        }
        else
        {
            buf->last_buf = 1;
        }
    }

    return ngx_http_next_body_filter(r, in);
}



// Initialization function, chain our filter on the global filter
// list
static ngx_int_t ngx_http_jsonp_filter_init( ngx_conf_t * cf )
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_jsonp_body_filter;
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_jsonp_header_filter;

    return NGX_OK;
}
